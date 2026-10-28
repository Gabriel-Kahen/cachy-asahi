#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Rehearse a signed synthetic repository pair offline in a new private directory.

Stable promotion is exercised as a required refusal. The separate rehearsal
selection uses the existing endpoint atomic-selection primitive; it grants no
stable, installed-system, trust-bootstrap, ARM or hardware acceptance.
"""
import argparse
import contextlib
from datetime import datetime, timezone
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


E = module('rehearsal_export', HERE / 'export_repository.py')
R = E.r
T = module('rehearsal_enroll', HERE.parent / 'repository/enroll.py')
S = module('rehearsal_expiry', HERE.parent / 'maintenance/signing_expiry.py')


def bounded(argv, env, timeout):
    """Terminate the owned command group on timeout or interruption."""
    with subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          start_new_session=True) as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate(timeout=10)
            raise
        return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)


def release_command(argv, *, env=None):
    """Real release-library subprocess runner with a rehearsal-only deadline."""
    result = bounded([str(value) for value in argv], env, 90)
    R.require(len(result.stdout) + len(result.stderr) <= 2 * 1024**2, 'command output bound')
    R.require(result.returncode == 0, 'command failed: ' + str(argv[0]) + ': ' +
              result.stderr.decode(errors='replace')[-3000:])
    return result.stdout


# Only this privately imported module instance uses the bounded runner. All
# archive, signature, dependency, provenance and stable-gate checks stay intact.
R.run = release_command


def fixture(directory, release_id, version):
    """Write deterministic, real package archive bytes; never run a recipe."""
    directory.mkdir()
    archive = directory / f'rehearsal-fixture-{version}-any.pkg.tar.gz'
    metadata = '\n'.join([
        'pkgname = rehearsal-fixture', f'pkgver = {version}',
        'pkgdesc = SYNTHETIC offline lifecycle fixture',
        'url = https://example.invalid/rehearsal', 'builddate = 1700000000',
        'packager = TEST ONLY', 'size = 8', 'arch = any', 'license = MIT',
        'depend = rehearsal-runtime>=2', ''])
    with archive.open('xb') as raw, gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w') as tar:
            for name, data in {'.PKGINFO': metadata.encode(),
                               'usr/share/rehearsal-fixture/version': (version + '\n').encode()}.items():
                entry = tarfile.TarInfo(name)
                entry.mode, entry.mtime, entry.size = 0o644, 1700000000, len(data)
                tar.addfile(entry, io.BytesIO(data))
    base = dict(schema_version=1, snapshot_id='synthetic-base', target_arch='aarch64',
                kind='complete-target-transaction', packages=[
                    dict(name='linux-asahi', version='TEST', arch='aarch64', depend=[],
                         provides=[], conflict=[], files=['boot/asahi-TEST-fixture']),
                    dict(name='rehearsal-runtime', version='2', arch='aarch64', depend=[],
                         provides=[], conflict=[], files=['usr/share/rehearsal-runtime/TEST'])])
    R.write(directory / 'base.json', base)
    R.write(directory / 'provenance.json', dict(
        schema_version=1, artifact_sha256=R.sha(archive),
        package=dict(name='rehearsal-fixture', version=version, arch='any'),
        source_commit='a' * 40, recipe_sha256='b' * 64, licenses=['MIT'],
        sources=[dict(url='fixture://synthetic-original', sha256='c' * 64)],
        build=dict(execution='synthetic', architecture='any', environment='TEST-only-no-build',
                   snapshot_id='synthetic-base')))
    def ref(name):
        return dict(path=name, sha256=R.sha(directory / name))
    release = dict(schema_version=1, release_id=release_id, synthetic=True,
                   target_arch='aarch64', repo_name='rehearsal', source_commit='a' * 40,
                   base=dict(ref('base.json'), snapshot_id='synthetic-base'),
                   packages=[dict(artifact=ref(archive.name), provenance=ref('provenance.json'))],
                   policy=dict(supported_models=['m2-air-13', 'm2-air-15'],
                               selected_packages=['rehearsal-fixture'], protected_packages=['linux-asahi'],
                               coordinated_sets=[dict(name='TEST-runtime', versions={'rehearsal-runtime': '2'})]),
                   evidence=[])
    R.write(directory / 'spec.json', release)
    return directory / 'spec.json'


@contextlib.contextmanager
def test_identity():
    # Always outside the checkout, never accepts an existing signing identity.
    with tempfile.TemporaryDirectory(prefix='cachy-asahi-TEST-rehearsal-', dir='/tmp') as temporary:
        home = Path(temporary)
        home.chmod(0o700)
        env = dict(PATH='/usr/bin:/bin', HOME=temporary, GNUPGHOME=temporary, LANG='C', LC_ALL='C')
        def gpg(*args):
            result = bounded(['/usr/bin/gpg', '--no-options', '--homedir', temporary,
                              '--batch', '--no-auto-key-retrieve', *args], env, 30)
            result.check_returncode()
            return result.stdout
        try:
            gpg('--pinentry-mode', 'loopback', '--passphrase', '', '--quick-generate-key',
                'TEST ONLY offline release rehearsal <rehearsal@example.invalid>', 'ed25519', 'sign', '1d')
            key = next(row.split(':')[9] for row in gpg('--with-colons', '--list-keys').decode().splitlines()
                       if row.startswith('fpr:'))
            yield home, key, gpg('--armor', '--export', key), env
        finally:
            bounded(['/usr/bin/gpgconf', '--homedir', temporary, '--kill', 'all'], env, 10).check_returncode()


def snapshot(directory):
    return {p.relative_to(directory).as_posix(): ('symlink', os.readlink(p)) if p.is_symlink()
            else ('file', R.sha(p)) for p in directory.rglob('*') if p.is_symlink() or p.is_file()}


def select_fixture(root, selection, rid, key, env, expected_current):
    """Private single-writer rehearsal selection, never a production/CAS API."""
    R.valid_name(rid)
    current = selection / 'current'
    observed = os.readlink(current) if current.is_symlink() else None
    R.require(observed == expected_current and (observed is not None or not current.exists()),
              'rehearsal selection changed')
    R.require(not (root / 'withdrawals' / f'{rid}.json').exists(), 'release withdrawn')
    directory = root / 'staging' / rid
    manifest, spec = R.verify_release(directory, key, env)
    R.require(manifest['release_id'] == rid and spec.get('synthetic') is True,
              'rehearsal selector accepts only matching synthetic staging fixtures')
    target = os.path.relpath(directory, selection)
    R.require(not E.select(selection, target), 'selection cleanup uncertain')
    return target


def rehearse(output):
    """All writes stay in the exclusively created output and temporary TEST homes."""
    output = E.canonical(str(output))
    missing = [name for name in ('gpg', 'gpgconf', 'repo-add', 'bsdtar', 'vercmp') if not shutil.which(name)]
    R.require(not missing, 'required installed tools unavailable: ' + ', '.join(missing))
    output.mkdir(mode=0o700)  # Never overwrite or clean an existing result.
    checks, commands = [], []
    report = dict(schema_version=1, purpose='offline-synthetic-release-lifecycle-rehearsal',
                  status='RUNNING', synthetic=True, host_arch=platform.machine(),
                  started_utc=datetime.now(timezone.utc).isoformat(), checks=checks, commands=commands,
                  stable_promotion='NOT_ACCEPTED', package_installation='NOT_RUN',
                  trust_bootstrap='NOT_RUN', signing_rotation='NOT_RUN', network_publication='NOT_RUN',
                  native_arm='NOT_RUN', generic_arm_16k='NOT_RUN', m2_air_13='NOT_RUN', m2_air_15='NOT_RUN')
    def checkpoint():
        R.write(output / 'report.json', report)
    def check(name, condition, **details):
        checks.append(dict(name=name, result='PASS' if condition else 'FAIL', **details))
        checkpoint()
        R.require(condition, 'rehearsal failed: ' + name)
    def refused(name, action, expected):
        try:
            action()
        except (R.Error, T.Error) as error:
            check(name, expected in str(error), observed_error=str(error))
        else:
            check(name, False, observed_error='operation unexpectedly succeeded')
    try:
        root, inputs, selection = (output / name for name in ('repository', 'inputs', 'rehearsal-selection'))
        for path in (root, inputs, selection):
            path.mkdir(mode=0o700)
        initial = fixture(inputs / 'initial', 'fixture-1', '1.0-1')
        successor = fixture(inputs / 'successor', 'fixture-2', '1.1-1')
        with test_identity() as (home, key, public, env):
            report['test_signer'] = key
            (output / 'TEST-public.asc').write_bytes(public)
            def cli(script, *arguments, success=True):
                argv = [sys.executable, '-I', '-B', str(script), *map(str, arguments)]
                result = bounded(argv, env, 90)
                entry = dict(argv=argv, returncode=result.returncode,
                             stdout=result.stdout.decode(errors='replace'), stderr=result.stderr.decode(errors='replace'))
                commands.append(entry)
                checkpoint()
                R.require(len(result.stdout) + len(result.stderr) <= 2 * 1024**2, 'command output bound')
                R.require((result.returncode == 0) == success, 'unexpected CLI result: ' + entry['stderr'][-2000:])
                return entry
            def release(*arguments, **kwargs):
                return cli(HERE / 'release.py', '--root', root, '--gpg-home', home, '--key', key,
                           *arguments, **kwargs)
            with tempfile.TemporaryDirectory(prefix='rehearsal-public-inspection-', dir='/tmp') as inspection:
                T.inspect_key(output / 'TEST-public.asc', key, Path(inspection))
                check('enrollment-certificate-inspection', True, trust='not established')
            now = int(datetime.now(timezone.utc).timestamp())
            expiry = S.report(S.inspect(public, now), key, now, 30)
            R.write(output / 'expiry-current.json', expiry)
            check('certificate-current-signing-window', expiry['signing_time_window'] == 'AVAILABLE_IN_EXPORT')
            deadline = expiry['keys'][0]['expires_epoch']
            expired = S.report(S.inspect(public, deadline), key, deadline, 30)
            R.write(output / 'expiry-deadline.json', expired)
            check('certificate-expiry-deadline', expired['signing_time_window'] == 'NO_USABLE_SIGNING_TIME_WINDOW_IN_EXPORT')
            for spec_path in (initial, successor):
                release('stage', '--spec', spec_path)
                rid = R.load(spec_path)['release_id']
                release('verify', '--release-id', rid)
                check('signed-stage-and-verify-' + rid, True)
            first, second = root / 'staging/fixture-1', root / 'staging/fixture-2'
            retained = snapshot(first)
            current = select_fixture(root, selection, 'fixture-1', key, env, None)
            comparison = cli(HERE / 'compare_releases.py', '--before', first, '--after', second,
                             '--gpg-home', home, '--key', key)
            difference = json.loads(comparison['stdout'])
            R.write(output / 'comparison.json', difference)
            check('changed-successor-verified', len(difference['packages']) == 1 and
                  difference['packages'][0]['change'] == 'upgraded' and
                  difference['packages'][0]['artifact_bytes_changed'])
            for rid in ('fixture-1', 'fixture-2'):
                gates = inputs / f'{rid}-gates.json'
                R.write(gates, dict(schema_version=1, release_id=rid, synthetic=True,
                                   release_sha256=R.sha(root / 'staging' / rid / 'release.json')))
                refusal = release('promote', '--release-id', rid, '--gates', gates, success=False)
                check('stable-promotion-refused-' + rid,
                      'synthetic fixtures cannot enter stable' in refusal['stderr'] and not (root / 'stable').exists())
            refused('wrong-signer-refused', lambda: R.verify_release(second, '0' * 40, env),
                    'signature does not match pinned fingerprint')
            partial = root / 'staging/fixture-partial'
            partial.mkdir()
            for name in ('release.json', 'release.json.sig'):
                shutil.copyfile(second / name, partial / name)
            refused('partial-successor-refused', lambda: select_fixture(root, selection, 'fixture-partial', key, env, current),
                    'release payload changed')
            check('partial-successor-preserves-selection', os.readlink(selection / 'current') == current)
            current = select_fixture(root, selection, 'fixture-2', key, env, current)
            check('successor-rehearsal-selection', (selection / 'current').resolve() == second)
            archive = next((second / 'repo').glob('*.pkg.tar.gz'))
            original = archive.read_bytes()
            archive.write_bytes(original + b'CORRUPTION-DRILL')
            refused('corrupt-successor-refused', lambda: R.verify_release(second, key, env), 'release payload changed')
            reason = inputs / 'incident.txt'
            reason.write_text('TEST ONLY: selected synthetic successor deliberately corrupted; recover fixture-1.\n')
            release('withdraw', '--release-id', 'fixture-2', '--reason', reason)
            withdrawal = root / 'withdrawals/fixture-2.json'
            R.verify_signature(withdrawal, key, env)
            check('signed-withdrawal-retains-corrupt-successor', archive.read_bytes() == original + b'CORRUPTION-DRILL' and
                  R.load(withdrawal)['packages_retained'] is True)
            refusal = release('verify', '--release-id', 'fixture-2', success=False)
            check('withdrawn-successor-verification-refused',
                  'release withdrawn; retained files are recovery evidence only' in refusal['stderr'])
            refused('withdrawn-successor-selection-refused',
                    lambda: select_fixture(root, selection, 'fixture-2', key, env, current), 'release withdrawn')
            current = select_fixture(root, selection, 'fixture-1', key, env, current)
            release('verify', '--release-id', 'fixture-1')
            check('recovered-retained-predecessor', (selection / 'current').resolve() == first and snapshot(first) == retained)
            receipt = output / 'recovery.json'
            R.write(receipt, dict(schema_version=1, synthetic=True, purpose='rehearsal-selection-recovery',
                                 from_release='fixture-2', to_release='fixture-1',
                                 predecessor_manifest_sha256=R.sha(first / 'release.json'),
                                 withdrawal_sha256=R.sha(withdrawal), selected_target=current,
                                 installed_system_restored=False, stable_accepted=False))
            R.sign(receipt, key, env)
            check('signed-recovery-receipt', True, sha256=R.sha(receipt))
            report['retained_predecessor_files'] = retained
            report['fixtures'] = {name: R.sha(path) for name, path in
                                  [('initial', next(initial.parent.glob('*.pkg.tar.gz'))),
                                   ('successor', next(successor.parent.glob('*.pkg.tar.gz')))]}
        report.update(status='PASS_SYNTHETIC_REHEARSAL', private_test_home_removed=not home.exists(),
                      completed_utc=datetime.now(timezone.utc).isoformat())
        check('temporary-test-home-removed', report['private_test_home_removed'])
        return report
    except BaseException as error:
        report.update(status='FAIL', error=str(error) or type(error).__name__)
        raise
    finally:
        checkpoint()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='new absolute output directory; existing paths refused')
    args = parser.parse_args(argv)
    try:
        report = rehearse(args.output)
        print(json.dumps(dict(status=report['status'], checks=len(report['checks']), output=str(args.output),
                              stable_promotion=report['stable_promotion']), sort_keys=True))
        return 0
    except (R.Error, T.Error, OSError, ValueError, subprocess.SubprocessError) as error:
        print('offline rehearsal failed: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(R.Error('interrupted by SIGTERM')))
    raise SystemExit(main())
