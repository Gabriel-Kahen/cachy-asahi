#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite container worker: provision signed extension or compile one variant."""
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import PREFIX, SOURCE, TOOLS, code_contract, delta_config, digest, inventory, load, module, need, regular, save
from runtime import Cancelled, Runner, cancellation_handlers, defer_signals
import inner_result

CODE, INPUTS, OUT = Path('/code'), Path('/inputs'), Path('/out')


def profile(action, contract):
    need(platform.system() == 'Linux' and platform.machine() in ('aarch64', 'arm64'), 'native container required')
    marker = Path('/.dockerenv'); regular(marker, 0)
    need(marker.stat().st_uid == 0 and os.getuid() == os.geteuid() and os.getgid() == os.getegid(), 'container identity required')
    expected = (0, 0) if action == 'provision' else (contract['uid'], contract['gid'])
    need((os.getuid(), os.getgid()) == expected, 'container uid/gid differs')
    text = Path('/proc/self/status').read_text()
    caps = {key: int(value, 16) for key, value in re.findall(r'^(Cap(?:Inh|Prm|Eff|Bnd|Amb)):\s+([0-9a-f]+)$', text, re.M)}
    need(len(caps) == 5 and re.search(r'^NoNewPrivs:\s+1$', text, re.M), 'container privilege profile differs')
    if action == 'provision':
        need(caps['CapEff'] == caps['CapPrm'] == caps['CapBnd'] == 0xb and caps['CapInh'] == caps['CapAmb'] == 0, 'provision capabilities differ')
    else:
        need(not any(caps.values()), 'build capabilities present')
    mounts = {}
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        before, after = line.split(' - ', 1); fields = before.split(); info = after.split()
        mounts[fields[4]] = {'options': fields[5].split(','), 'type': info[0]}
    need(mounts.get('/tmp', {}).get('type') == 'tmpfs' and all(path in mounts for path in ('/code', '/inputs', '/out')), 'exact bind/tmpfs mounts required')
    need(all('ro' in mounts[path]['options'] for path in ('/code', '/inputs')) and 'rw' in mounts['/out']['options'], 'mount access differs')
    need(('rw' if action == 'provision' else 'ro') in mounts['/']['options'], 'root access differs')
    cgroup = Path('/sys/fs/cgroup')
    memory = int((cgroup / 'memory.max').read_text().strip())
    swap = int((cgroup / 'memory.swap.max').read_text().strip())
    pids = int((cgroup / 'pids.max').read_text().strip())
    quota, period = map(int, (cgroup / 'cpu.max').read_text().split())
    need(memory == 14 * 1024**3 and swap == 0 and pids == 512 and quota == 2 * period and period > 0,
         'actual cgroup v2 limits differ')
    space = os.statvfs('/tmp'); scratch = space.f_frsize * space.f_blocks
    need(11 * 1024**3 <= scratch <= 12 * 1024**3, 'actual tmpfs disk ceiling differs')
    return {'architecture': platform.machine(), 'inspection_page_bytes': os.sysconf('SC_PAGE_SIZE'),
            'uid': os.getuid(), 'gid': os.getgid(), 'capabilities': caps,
            'cgroup_v2': {'memory_max': memory, 'memory_swap_max': swap, 'pids_max': pids,
                          'cpu_quota': quota, 'cpu_period': period}, 'scratch_max_bytes': scratch,
            'mounts': {p: mounts[p] for p in ('/', '/tmp', '/code', '/inputs', '/out')}}


def observe(report, operation, *args, deferred=None, **kwargs):
    row = report.get('inner_diagnostic')
    if row is None: return
    try:
        operation(row, *args, **kwargs)
    except (Cancelled, KeyboardInterrupt, SystemExit) as error:
        row.update(write_failed=True, cancelled=True)
        if deferred is None: raise
        report.update(status='FAIL', cancelled=True)
        deferred.append(error)
    except Exception:
        # Ordinary diagnostic faults cannot change the original business path.
        row['write_failed'] = True
    except BaseException as error:
        # Non-Exception controls are delivered or retained, never swallowed.
        row.update(write_failed=True, cancelled=True)
        report.update(status='FAIL', cancelled=True)
        if deferred is None: raise
        deferred.append(error)




def observe_failure(report, error, cleanup, deferred):
    def record(row):
        # Freeze the original cause before invoking the optional helper callback.
        if isinstance(error, (Cancelled, KeyboardInterrupt, SystemExit)): kind = 'CANCELLED'
        elif isinstance(error, ImportError): kind = 'IMPORT'
        elif isinstance(error, OSError): kind = 'IO'
        elif type(error) is ValueError:
            kind = {'command-timeout': 'TIMEOUT', 'deadline-exhausted': 'DEADLINE',
                'output-bound': 'OUTPUT_BOUND', 'process-cleanup': 'PROCESS_CLEANUP'}.get(
                    error.args[0] if len(error.args) == 1 and type(error.args[0]) is str else '', 'DATA_REFUSAL')
        else: kind = 'OTHER'
        key = 'cleanup_failure' if cleanup else 'first_failure'
        if row[key] is None:
            row[key] = {'phase': row['phase'], 'command': row['command'], 'error_kind': kind}
        if kind == 'CANCELLED': row['cancelled'] = True
        inner_result.failure(row, error, cleanup=cleanup)
    observe(report, record, deferred=deferred)


def command(runner, report, label, argv, timeout=60):
    if 'inner_diagnostic' in report:
        name = {'inventory': 'INVENTORY', 'config': 'CONFIG', 'kernel': 'KERNEL'}.get(label)
        if label.startswith('tool-') and label[5:].isdigit(): name = 'TOOL_' + label[5:]
        observe(report, inner_result.issued, name)
    result = runner.run(argv, timeout=timeout, log=label + '.log')
    if 'inner_diagnostic' in report:
        if isinstance(result, subprocess.CompletedProcess):
            observe(report, inner_result.returned, result.returncode)
        else:
            observe(report, inner_result.invalidate)
    report['commands'].append({'label': label, 'argv': argv, 'exit': result.returncode,
                              'log_sha256': digest(runner.log_dir / (label + '.log'))})
    try:
        need(result.returncode == 0, 'command failed: ' + label)
    except BaseException as first:
        if type(label) is str and label == 'kernel':
            if type(result) is subprocess.CompletedProcess and type(result.returncode) is int:
                if result.returncode != 0:
                    controls = []
                    observe_failure(report, first, False, controls)
                    observe(report, inner_result.compiler_failure, result.stdout,
                            report['commands'][-1]['log_sha256'], deferred=controls)
                    if controls:
                        prior_cause = first.__cause__
                        causes = ([prior_cause] if prior_cause is not None else []) + controls
                        first.__cause__ = BaseExceptionGroup('compiler diagnostic controls', causes)
        raise
    return result.stdout


def package_map(runner, report, expected, label='inventory'):
    data = command(runner, report, label, ['/usr/bin/pacman', '--config', '/tmp/query.conf', '-Q'])
    rows = b''.join(sorted(data.splitlines(keepends=True)))
    need(inventory(rows) == inventory(expected.encode()), 'complete builder inventory differs')
    return {'sha256': __import__('hashlib').sha256(rows).hexdigest(), 'count': len(inventory(rows))}


def provision(runner, report, dependencies):
    # Cryptographic verification repeats inside the network-off provisioner.
    home = Path('/tmp/public-gpg'); home.mkdir(mode=0o700)
    gpg = ['/usr/bin/gpg', '--batch', '--no-options', '--homedir', str(home), '--no-auto-key-retrieve', '--no-autostart']
    command(runner, report, 'key-import', gpg + ['--import', '/inputs/archlinuxarm.gpg'])
    statuses = []
    for index, row in enumerate(dependencies['packages']):
        archive = INPUTS / row['filename']; sig = archive.with_name(archive.name + '.sig')
        regular(archive, 800 * 1024**2); regular(sig, 65536)
        need(digest(archive) == row['sha256'] and digest(sig) == row['signature_sha256'], 'signed package differs')
        output = command(runner, report, 'signature-' + str(index), gpg + ['--status-fd', '1', '--verify', str(sig), str(archive)])
        valid = re.findall(rb'^\[GNUPG:\] VALIDSIG (.+)$', output, re.M)
        need(len(valid) == 1 and valid[0].split()[-1].decode() == dependencies['signer_fingerprint'] and
             not re.search(rb'\[GNUPG:\] (?:BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG)', output), 'signature signer/status differs')
        statuses.append({'name': row['name'], 'sha256': row['sha256'], 'signature_sha256': row['signature_sha256']})
    # All15 inspected archives have no hook or scriptlet. Mask existing default
    # hook identities too; the strict private config registers no repositories.
    hooks = Path('/tmp/no-hooks'); hooks.mkdir()
    for directory in ('/usr/share/libalpm/hooks', '/etc/pacman.d/hooks'):
        for path in Path(directory).glob('*.hook'):
            need(re.fullmatch(r'[A-Za-z0-9_.+-]+\.hook', path.name), 'hook identity differs')
            target = hooks / path.name
            if not target.exists() and not target.is_symlink(): target.symlink_to('/dev/null')
    # GPG verification above authenticates exact files. Pacman gets an isolated
    # public-only trusted keyring; no host/default trust or network retrieval.
    trust = Path('/tmp/ownertrust'); trust.write_text(dependencies['signer_fingerprint'] + ':6:\n')
    result = runner.run(gpg + ['--import-ownertrust', str(trust)], timeout=30, log='ownertrust.log')
    need(result.returncode == 0, 'private trust initialization failed')
    conf = Path('/tmp/install.conf')
    conf.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\nGPGDir = /tmp/public-gpg\nCacheDir = /tmp/package-cache\nHookDir = /tmp/no-hooks\n')
    Path('/tmp/package-cache').mkdir()
    before = package_map(runner, report, load(INPUTS / 'contract.json')['base_inventory'], 'inventory-before')
    command(runner, report, 'install', ['/usr/bin/pacman', '--config', str(conf), '--noconfirm', '--noscriptlet', '-U',
                                      *(str(INPUTS / row['filename']) for row in dependencies['packages'])], timeout=600)
    # Package cache/key/trust/config live in tmpfs and cannot enter commit.
    report['base_inventory'] = before
    report['installed_inventory'] = package_map(runner, report, dependencies['expected_inventory'], 'inventory-after')
    report['signatures'] = statuses
    command(runner, report, 'database-check', ['/usr/bin/pacman', '--config', '/tmp/query.conf', '-Dk'])
    command(runner, report, 'ldconfig', ['/usr/bin/ldconfig'])


def tools(runner, report):
    result = {}
    for index, name in enumerate(TOOLS):
        path = Path('/usr/bin') / name; target = path.resolve(); regular(target, 256 * 1024**2)
        output = command(runner, report, 'tool-' + str(index), [str(path), '--version'])
        result[name] = {'path': str(path), 'resolved': str(target), 'sha256': digest(target),
                        'version_output': output.decode('utf-8', errors='strict')[:4096]}
    return result


def configuration_delta(verifier, before_path, after_path, policy, report):
    """Preserve the original two reads, allowlist and failure; add no actor or clock."""
    before = after = None
    stage = 'BEFORE_CONFIG_PARSE'
    try:
        before = verifier.config(before_path)
        stage = 'AFTER_CONFIG_PARSE'
        after = verifier.config(after_path)
        stage = 'DELTA_COMPARE'
        return delta_config(before, after, policy)
    except BaseException as first:
        controls = []
        try:
            observe_failure(report, first, False, controls)
            observe(report, inner_result.config_failure, stage, before, after, policy, deferred=controls)
        except BaseException as secondary:
            row = report.get('inner_diagnostic')
            if row is not None:
                row['write_failed'] = True
                if isinstance(secondary, (Cancelled, KeyboardInterrupt, SystemExit)):
                    row['cancelled'] = True
                    report.update(cancelled=True)
            controls.append(secondary)
        raise


def compile_variant(runner, report, contract, dependencies, action):
    observe(report, inner_result.phase, 'SOURCE')
    held = CODE / SOURCE
    sys.path.insert(0, str(held))
    harness = module('harness', held / 'harness.py')
    verifier = module('kernel_output_verifier', held / 'verify_build.py')
    harness.ROOT = Path('/tmp')
    source_out = Path('/tmp/artifacts/kernel-candidates/trial')
    import argparse
    source_result = harness.run(argparse.Namespace(mode='apply' if action == 'candidate' else 'baseline', full_source=True,
        lock=held / 'candidate.json', lock_sha256=contract['candidate_sha256'], archive=INPUTS / 'asahi.tar.gz',
        config=INPUTS / 'embedded-config', patch=INPUTS / 'candidate.patch', output=source_out))
    need(source_result['full_source_tree'] is True, 'complete source required')
    source = source_out / 'source-tree' / 'linux-asahi-7.1.13-3'; build = Path('/tmp/build'); build.mkdir()
    shutil.copyfile(INPUTS / 'embedded-config', build / '.config')
    make = ['/usr/bin/make', '-C', str(source), 'O=' + str(build), 'ARCH=arm64',
            'LOCALVERSION=-cachy-asahi-kernel-c01', 'CC=/usr/bin/gcc', 'HOSTCC=/usr/bin/gcc',
            'LD=/usr/bin/ld', 'AS=/usr/bin/as', 'RUSTC=/usr/bin/rustc', 'BINDGEN=/usr/bin/bindgen',
            'PAHOLE=/usr/bin/pahole', 'CLANG=/usr/bin/clang', 'DTC=/usr/bin/dtc']
    report['source'] = source_result
    observe(report, inner_result.phase, 'CONFIG')
    command(runner, report, 'config', make + ['olddefconfig'], timeout=300)
    observe(report, inner_result.phase, 'CONFIG_DELTA')
    report['generated_config_delta'] = configuration_delta(verifier, INPUTS / 'embedded-config', build / '.config', dependencies['allowed_generated_config_delta'], report)
    if action == 'candidate':
        observe(report, inner_result.phase, 'PAIRED_CONFIG')
        regular(INPUTS / 'baseline-config', 1024**2)
        report['paired_config'] = verifier.verify_config(INPUTS / 'baseline-config', build / '.config')
    observe(report, inner_result.phase, 'GENERATED_CONFIG')
    shutil.copyfile(build / '.config', OUT / 'generated-config.txt')
    observe(report, inner_result.phase, 'KERNEL')
    command(runner, report, 'kernel', make + ['-j2', 'Image', 'modules', 'dtbs'], timeout=7200)
    observe(report, inner_result.phase, 'OUTPUTS')
    report['structure'] = verifier.verify_outputs(build, source, build / '.config')
    report['native_kernel_compilation'] = 'PASS'
    report['kernel_execution'] = 'NOT RUN'


def execute(action, nonce=None, contract_sha=None):
    nonce = os.environ.get('KERNEL_STAGE_NONCE', '') if nonce is None else nonce
    contract_sha = os.environ.get('KERNEL_STAGE_CONTRACT_SHA256') if contract_sha is None else contract_sha
    need(re.fullmatch('[0-9a-f]{32}', nonce) and (action == 'provision' or os.environ.get('KERNEL_STAGE_ACTION') == action), 'worker action/nonce differs')
    need(re.fullmatch('[0-9a-f]{64}', contract_sha or ''), 'worker contract pin required')
    contract = load(INPUTS / 'contract.json', contract_sha)
    need(contract['nonce'] == nonce, 'worker contract differs')
    code_contract(CODE, contract['files'])
    dependencies = load(CODE / (PREFIX + 'dependencies.json'), contract['dependencies_sha256'])
    for name, row in contract['inputs'].items():
        regular(INPUTS / name, 800 * 1024**2)
        need(digest(INPUTS / name) == row['sha256'], 'input snapshot differs: ' + name)
    report = {'status': 'FAIL', 'action': action, 'nonce': nonce, 'commands': [], 'cancelled': False,
              'kernel_execution': 'NOT RUN', 'hardware_validation': 'NOT RUN', 'performance': 'NOT MEASURED'}
    if action != 'provision':
        try:
            report['inner_diagnostic'] = inner_result.initial({'nonce': nonce, 'action': action,
                'contract_sha256': contract_sha, 'worker_sha256': contract['files'][PREFIX + 'worker.py']['sha256']})
        except Exception:
            report['inner_diagnostic'] = None
    Path('/tmp/home').mkdir(mode=0o700)
    Path('/tmp/query.conf').write_text('[options]\nArchitecture = aarch64\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\n')
    env = {'PATH': '/usr/bin:/bin', 'HOME': '/tmp/home', 'LC_ALL': 'C', 'TZ': 'UTC', 'TMPDIR': '/tmp',
           'KBUILD_BUILD_USER': 'cachy-asahi-kernel-c01', 'KBUILD_BUILD_HOST': 'native-kernel-c01', 'KBUILD_BUILD_VERSION': '1',
           'KBUILD_BUILD_TIMESTAMP': 'Sat Sep 19 16:04:41 UTC 2026', 'RUST_LIB_SRC': '/usr/lib/rustlib/src/rust/library', 'LIBCLANG_PATH': '/usr/lib'}
    runner = Runner(7700 if action in ('baseline', 'candidate') else 900, env, Path('/tmp/logs'))
    observation_controls = []
    try:
        observe(report, inner_result.phase, 'PROFILE')
        report['profile'] = profile(action, contract)
        if action == 'provision':
            provision(runner, report, dependencies)
        else:
            observe(report, inner_result.phase, 'INVENTORY')
            report['inventory'] = package_map(runner, report, dependencies['expected_inventory'])
            observe(report, inner_result.phase, 'TOOLS')
            report['tools'] = tools(runner, report)
            if action == 'probe':
                observe(report, inner_result.phase, 'SOURCE')
                regression = module('kernel_regression', CODE / (PREFIX + 'regression.py'))
                report['logic_fixture'] = regression.run_fixture(INPUTS / 'bio-baseline.c', INPUTS / 'bio-candidate.c',
                    Path('/tmp/logic/trial'), Path('/usr/bin/gcc').resolve(), digest(Path('/usr/bin/gcc').resolve()), evidence_root=Path('/tmp/logic'))
                need(report['logic_fixture']['status'] == 'PASS', 'native logic fixture failed')
                report['logic_fixture_kind'] = 'userspace stubs around exact extracted functions; not kernel execution'
                text_out = OUT / 'logic-text'; text_out.mkdir(mode=0o700)
                retained = 0
                for path in Path('/tmp/logic/trial').iterdir():
                    if path.name == 'result.json' or path.name.endswith(('.c', '.command.json', '.stdout', '.stderr')):
                        regular(path, 1024**2); retained += path.stat().st_size
                        need(retained <= 4 * 1024**2, 'logic evidence size bound')
                        shutil.copyfile(path, text_out / path.name)
            else:
                compile_variant(runner, report, contract, dependencies, action)
        report['status'] = 'PASS'
    except BaseException as error:
        report.update(status='FAIL', cancelled=report.get('cancelled') is True or isinstance(error, (Cancelled, KeyboardInterrupt, SystemExit)), error_type=type(error).__name__)
        try:
            observe_failure(report, error, False, observation_controls)
        except (Cancelled, KeyboardInterrupt, SystemExit) as error:
            row = report.get('inner_diagnostic')
            if row is not None:
                row.update(write_failed=True, cancelled=True)
            report.update(status='FAIL', cancelled=True)
            observation_controls.append(error)
        except Exception:
            row = report.get('inner_diagnostic')
            if row is not None:
                row['write_failed'] = True
        raise
    finally:
        original_failure = sys.exc_info()[1]
        try:
            observe(report, inner_result.phase, 'FINALIZATION', deferred=observation_controls)
        except (Cancelled, KeyboardInterrupt, SystemExit) as error:
            row = report.get('inner_diagnostic')
            if row is not None:
                row.update(write_failed=True, cancelled=True)
            report.update(status='FAIL', cancelled=True)
            observation_controls.append(error)
        except Exception:
            row = report.get('inner_diagnostic')
            if row is not None:
                row['write_failed'] = True
        try:
            with defer_signals() as events:
                for log in runner.log_dir.glob('*.log'):
                    regular(log, 8 * 1024**2); shutil.copyfile(log, OUT / log.name)
                if events:
                    report.update(status='FAIL', cancelled=True)
                    try:
                        observe_failure(report, Cancelled(events[0]), True, observation_controls)
                    except (Cancelled, KeyboardInterrupt, SystemExit) as error:
                        row = report.get('inner_diagnostic')
                        if row is not None:
                            row.update(write_failed=True, cancelled=True)
                        report.update(status='FAIL', cancelled=True)
                        observation_controls.append(error)
                    except Exception:
                        row = report.get('inner_diagnostic')
                        if row is not None:
                            row['write_failed'] = True
                if report['status'] == 'PASS':
                    try:
                        observe(report, inner_result.phase, 'COMPLETE', deferred=observation_controls)
                    except (Cancelled, KeyboardInterrupt, SystemExit) as error:
                        row = report.get('inner_diagnostic')
                        if row is not None:
                            row.update(write_failed=True, cancelled=True)
                        report.update(status='FAIL', cancelled=True)
                        observation_controls.append(error)
                    except Exception:
                        row = report.get('inner_diagnostic')
                        if row is not None:
                            row['write_failed'] = True
                save(OUT / 'result.json', report)
                if action == 'provision':
                    for path in OUT.iterdir():
                        regular(path, 8 * 1024**2)
                        path.chmod(0o600); os.chown(path, contract['uid'], contract['gid'])
            if events:
                report.update(status='FAIL', cancelled=True)
                try:
                    observe_failure(report, Cancelled(events[0]), True, observation_controls)
                except (Cancelled, KeyboardInterrupt, SystemExit) as error:
                    row = report.get('inner_diagnostic')
                    if row is not None:
                        row.update(write_failed=True, cancelled=True)
                    report.update(status='FAIL', cancelled=True)
                    observation_controls.append(error)
                except Exception:
                    row = report.get('inner_diagnostic')
                    if row is not None:
                        row['write_failed'] = True
                with defer_signals(): save(OUT / 'result.json', report)
                if action == 'provision': os.chown(OUT / 'result.json', contract['uid'], contract['gid'])
        except BaseException as error:
            try:
                observe_failure(report, error, True, observation_controls)
            except (Cancelled, KeyboardInterrupt, SystemExit) as error:
                row = report.get('inner_diagnostic')
                if row is not None:
                    row.update(write_failed=True, cancelled=True)
                report.update(status='FAIL', cancelled=True)
                observation_controls.append(error)
            except Exception:
                row = report.get('inner_diagnostic')
                if row is not None:
                    row['write_failed'] = True
            raise
        if observation_controls and original_failure is None: raise observation_controls[0]
    return 0


if __name__ == '__main__':
    try:
        need((len(sys.argv) == 4 and sys.argv[1] == 'provision') or
             (len(sys.argv) == 2 and sys.argv[1] in ('probe', 'baseline', 'candidate')), 'finite worker action required')
        with cancellation_handlers():
            raise SystemExit(execute(sys.argv[1], *sys.argv[2:]))
    except (Exception, Cancelled):
        print('kernel native worker failed', file=sys.stderr); raise SystemExit(1)
