#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stage/move the finite runtime and exercise a real signed TEST transition offline."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

sys.dont_write_bytecode = True


def run(argv, **kwargs):
    result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=90, **kwargs)
    assert result.returncode == 0, result.stdout.decode(errors='replace') + result.stderr.decode(errors='replace')
    return result.stdout


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def tree(root):
    return {str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*') if p.is_file()}


def check(recipe, srcdir, hide):
    with tempfile.TemporaryDirectory(prefix='repository-enrollment-v4-package-') as temporary:
        work = Path(temporary)
        staged, moved = work / 'staged', work / 'moved'
        run(['bash', '--noprofile', '--norc', '-c',
             'set -eu; umask 022; source "$1/PKGBUILD"; srcdir=$2; pkgdir=$3; package',
             'stage-enrollment-v4', recipe, srcdir, staged])
        staged.rename(moved)
        cli = moved / 'usr/bin/cachy-asahi-repository-enrollment'
        runtime = moved / 'usr/lib/cachy-asahi/repository-enrollment'
        provenance = json.loads((srcdir / 'source-provenance.json').read_bytes())
        payload = json.loads((srcdir / 'payload-map.json').read_bytes())
        expected = {'usr/bin/cachy-asahi-repository-enrollment',
                    *('usr/lib/cachy-asahi/repository-enrollment/' + name for name in payload['files']),
                    *('usr/share/doc/cachy-asahi-repository-enrollment/' + name
                      for name in ('README.md', 'source-provenance.json', 'payload-map.json')),
                    *('usr/share/licenses/cachy-asahi-repository-enrollment/' + name for name in ('LICENSE', 'NOTICE'))}
        inventory = tree(moved)
        assert set(inventory) == expected and len(expected) == 16
        assert cli.stat().st_mode & 0o777 == 0o755
        assert len(provenance['files']) == len(payload['files']) == 10
        assert len(provenance['base_runtime']['files']) == 9
        assert set(provenance['files']) == set(provenance['base_runtime']['files']) | {'scripts/repository/refresh.py'}
        assert all(provenance['files'][name] == row for name, row in provenance['base_runtime']['files'].items())
        archive = srcdir / 'private-source.tar.gz'
        assert archive.read_bytes()[4:8] == b'\0' * 4
        with tarfile.open(archive) as retained:
            members = retained.getmembers()
            assert [row.name for row in members] == ['private/' + name for name in sorted(payload['files'])]
            assert all(row.isfile() and row.mode == 0o644 and row.uid == row.gid == row.mtime == 0
                       and row.uname == row.gname == '' for row in members)
        assert 'scripts/release/compare_releases_v2.py' in payload['files']
        assert 'scripts/release/compare_releases.py' not in payload['files']
        for name, row in provenance['files'].items():
            body = (runtime / name).read_bytes()
            assert body == (srcdir / 'private' / name).read_bytes()
            assert len(body) == row['bytes'] and hashlib.sha256(body).hexdigest() == row['sha256']
            assert (runtime / name).stat().st_mode & 0o777 == 0o644
            assert payload['files'][name] == row

        # The sole helper is check-only. It builds signed synthetic bundles with
        # the exact frozen runtime; neither helper nor bootstrap is installed.
        bootstrap = work / 'bootstrap'
        shutil.copytree(srcdir / 'private', bootstrap)
        shutil.copyfile(srcdir / 'test_release.py', bootstrap / 'scripts/release/test_release.py')
        fixture = module('enrollment_v4_signed_fixture', bootstrap / 'scripts/release/test_release.py')
        bridge = module('enrollment_v4_fixture_bridge', bootstrap / 'scripts/repository/transition.py')
        fixture.ReleaseTests.setUpClass()
        case = fixture.ReleaseTests('test_source_delivery_assembles_stages_and_verifies_retained_materials')
        next_home = work / 'next-signer';next_home.mkdir(mode=0o700)
        revoked_home = work / 'revoked-public';revoked_home.mkdir(mode=0o700)
        try:
            case.setUp()
            # Exercise libarchive's zstd path, independently of Python's
            # compression-module version and with no zstd CLI invocation.
            extracted = work / 'package-input';extracted.mkdir()
            run(['bsdtar', '-xf', case.archive, '-C', extracted])
            archive = case.inputs / 'fixture-1.0-1-any.pkg.tar.zst'
            run(['bsdtar', '--zstd', '-cf', archive, '-C', extracted, '.PKGINFO', 'usr/share/fixture/config'])
            assert archive.read_bytes()[:4] == b'\x28\xb5\x2f\xfd'
            case.archive, case.digest = archive, fixture.r.sha(archive)
            record = fixture.r.load(case.inputs / 'provenance.json')
            record['artifact_sha256'] = case.digest
            case.put('provenance.json', record)
            case.release_spec['packages'][0]['artifact'] = case.ref(archive.name)
            case.release_spec['packages'][0]['provenance'] = case.ref('provenance.json')
            case.release_spec['repo_name'] = 'cachy-asahi'
            case.source_delivery_fixture()
            case.release_spec['release_id'] = 'before'
            case.stage();before = case.directory
            old_key, old_env = case.key, case.env
            old_public = work / 'old-public.asc'
            old_public.write_bytes(fixture.r.run(['gpg', '--batch', '--export', old_key], env=old_env))
            next_env = fixture.r.gpg_env(next_home, case.root)
            fixture.r.run(['gpg', '--batch', '--pinentry-mode', 'loopback', '--passphrase', '',
                           '--quick-generate-key', 'DISPOSABLE INSTALLED TRANSITION TEST <next@invalid>',
                           'ed25519', 'sign', '1d'], env=next_env)
            listing = fixture.r.run(['gpg', '--batch', '--with-colons', '--list-keys'], env=next_env).decode()
            next_key = next(line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:'))
            next_public = work / 'new-public.asc'
            next_public.write_bytes(fixture.r.run(['gpg', '--batch', '--export', next_key], env=next_env))
            case.key, case.env = next_key, next_env
            case.release_spec['release_id'] = 'after'
            case.stage();after = case.directory
            bundle = work / 'transition'
            now = datetime.now(timezone.utc).replace(microsecond=0)
            stamp = lambda value: value.isoformat().replace('+00:00', 'Z')
            bridge.T.create(argparse.Namespace(before=before, after=after, old_key=old_key, new_key=next_key,
                old_certificate=old_public, new_certificate=next_public, old_gpg_home=fixture.ReleaseTests.home,
                new_gpg_home=next_home, output=bundle, not_before=stamp(now - timedelta(minutes=1)),
                not_after=stamp(now + timedelta(hours=1)), as_of=stamp(now)))

            target = work / 'target'
            ring = target / 'etc/pacman.d/gnupg';ring.mkdir(parents=True, mode=0o700)
            (ring / 'pubring.gpg').touch(mode=0o600)
            (target / 'var/lib/pacman').mkdir(parents=True)
            ring_env = dict(os.environ, GNUPGHOME=str(ring))
            fixture.r.run(['gpg', '--batch', '--no-autostart', '--import', old_public], env=ring_env)
            ownertrust = work / 'ownertrust'
            ownertrust.write_text(old_key + ':6:\n')
            fixture.r.run(['gpg', '--batch', '--no-autostart', '--import-ownertrust', ownertrust], env=ring_env)
            fixture.r.run(['gpg', '--batch', '--no-autostart', '--check-trustdb'], env=ring_env)
            E = bridge.load_rotation().E
            url = 'https://repo.example.invalid/generations/' + 'a' * 64 + '/release/repo'
            (target / 'etc/pacman.conf').write_bytes(b'[options]\nArchitecture = auto\n' + E.BLOCK)
            (target / E.INCLUDE.lstrip('/')).write_bytes(E.config(url, old_key, E.sha(old_public.read_bytes())))

            poison = work / 'hostile';poison.mkdir()
            for name in ('json.py', 'argparse.py', 'sitecustomize.py'):
                (poison / name).write_text('raise RuntimeError("caller Python code must not execute")\n')
            environment = dict(os.environ, PYTHONPATH=str(poison), PYTHONHOME=str(poison))
            # Rebind work before hiding bootstrap so no later bind re-exposes it.
            prefix = ['bwrap', '--unshare-net', '--ro-bind', '/', '/', '--proc', '/proc', '--dev', '/dev',
                      '--tmpfs', '/tmp', '--bind', str(work), str(work),
                      '--ro-bind', str(case.base), str(case.base), '--chdir', str(poison)]
            hidden = {hide.resolve(), recipe.resolve(), srcdir.resolve(), bootstrap.resolve()}
            hidden = sorted((path for path in hidden if not any(path != other and path.is_relative_to(other)
                                                                for other in hidden)), key=str)
            for path in hidden:prefix += ['--tmpfs', str(path)]
            proof = run([*prefix, '/usr/bin/python3', '-I', '-B', '-c',
                         'import pathlib,socket,sys; assert all(not list(pathlib.Path(p).iterdir()) for p in sys.argv[1:]); '
                         'assert [name for _,name in socket.if_nameindex()]==["lo"]', *hidden], env=environment)
            assert proof == b''
            for args in (['--help'], ['--version'], ['configure', '--help'], ['rotate', '--help'], ['transition', '--help'], ['revoke', '--help'], ['refresh', '--help']):
                assert run([*prefix, cli, *args], env=environment)
            assert run([*prefix, cli, '--version'], env=environment).strip() == b'cachy-asahi-repository-enrollment 0.4.0'
            state = tree(target)
            command = [*prefix, cli, 'transition', '--root', target, '--bundle', bundle,
                       '--before', before, '--after', after, '--expected-current-fingerprint', old_key,
                       '--fingerprint', next_key]
            report = json.loads(run(command, env=environment))
            assert report['status'] == 'preview' and report['snapshot_url'] == url
            assert report['before']['release_id'] == 'before' and report['after']['release_id'] == 'after'
            assert not report['config_changed'] and not report['keyring_may_have_changed']
            assert not report['snapshot_upgrade_accepted'] and not report['production_accepted']
            assert tree(target) == state
            signature = bundle / 'old.sig';original = signature.read_bytes();signature.write_bytes(b'bad')
            refused = subprocess.run(list(map(str, command)), capture_output=True, timeout=90, env=environment)
            assert refused.returncode == 1, refused.stdout + refused.stderr
            assert json.loads(refused.stdout)['status'] == 'failed' and tree(target) == state
            signature.write_bytes(original)
            # Generate an updated public certificate in a public-only TEST home.
            # No private fixture key is copied into the installed runtime/target.
            revoke_env = fixture.r.gpg_env(revoked_home, case.root)
            fixture.r.run(['gpg', '--batch', '--no-autostart', '--import', old_public], env=revoke_env)
            raw = (fixture.ReleaseTests.home / 'openpgp-revocs.d' / (old_key + '.rev')).read_text()
            detached = work / 'test-revocation.asc'
            detached.write_text(raw[raw.index(':-----BEGIN PGP PUBLIC KEY BLOCK-----'):].replace(':-----BEGIN', '-----BEGIN', 1))
            fixture.r.run(['gpg', '--batch', '--no-autostart', '--import', detached], env=revoke_env)
            original_input = target / 'etc/pacman.d/operator-public.gpg'
            original_input.write_bytes(old_public.read_bytes());original_input.chmod(0o600)
            updated_input = target / 'etc/pacman.d/operator-revoked-public.gpg'
            updated_input.write_bytes(fixture.r.run(['gpg', '--batch', '--no-autostart', '--export', old_key], env=revoke_env))
            updated_input.chmod(0o600)
            state = tree(target)
            # The root-owned-input contract is exercised through mapped-root
            # user namespaces only; no privileged host mutation or fallback.
            revocation_command = [*prefix, '/usr/bin/unshare', '--user', '--map-root-user', '--', cli, 'revoke',
                '--root', target, '--expected-current-fingerprint', old_key,
                '--expected-current-certificate-sha256', E.sha(old_public.read_bytes()),
                '--current-public-key', original_input, '--revoked-public-key', updated_input]
            revoked = json.loads(run(revocation_command, env=environment))
            assert revoked['status'] == 'preview' and revoked['verified_primary_revocations'] == 1
            assert revoked['repository_enabled'] and not revoked['config_may_have_changed'] and not revoked['keyring_may_have_changed']
            assert not revoked['production_accepted'] and tree(target) == state
            genuine = updated_input.read_bytes();updated_input.write_bytes(original_input.read_bytes())
            bad_state = tree(target)
            refused = subprocess.run(list(map(str, revocation_command)), capture_output=True, timeout=90, env=environment)
            assert refused.returncode == 1, refused.stdout + refused.stderr
            assert json.loads(refused.stdout)['status'] == 'failed' and tree(target) == bad_state
            updated_input.write_bytes(genuine)
            assert tree(target) == state
            # A genuine renewed same-primary certificate and signing subkey.
            # Both keys remain outside package/runtime and the fixture is offline.
            fixture.r.run(['gpg', '--batch', '--pinentry-mode', 'loopback', '--passphrase', '',
                           '--quick-set-expire', old_key, '2d'], env=old_env)
            fixture.r.run(['gpg', '--batch', '--pinentry-mode', 'loopback', '--passphrase', '',
                           '--quick-add-key', old_key, 'ed25519', 'sign', '2d'], env=old_env)
            renewed_input = target / 'etc/pacman.d/renewed-public.gpg'
            renewed_input.write_bytes(fixture.r.run(['gpg', '--batch', '--export', old_key], env=old_env));renewed_input.chmod(0o600)
            message = work / 'renewal-message';message.write_bytes(b'Disposable packaged refresh check.\n')
            signature = work / 'renewal-message.sig'
            fixture.r.run(['gpg', '--batch', '--pinentry-mode', 'loopback', '--passphrase', '', '--local-user', old_key,
                           '--output', signature, '--detach-sign', message], env=old_env)
            verify = ['gpg', '--batch', '--no-auto-key-retrieve', '--homedir', ring, '--status-fd=1', '--verify', signature, message]
            assert subprocess.run(list(map(str, verify)), capture_output=True, timeout=90).returncode != 0
            refresh = [*prefix, '/usr/bin/unshare', '--user', '--map-root-user', '--', cli, 'refresh',
                       '--root', target, '--fingerprint', old_key, '--expected-current-certificate-sha256', E.sha(old_public.read_bytes()),
                       '--current-public-key', original_input, '--public-key', renewed_input]
            state = tree(target);before_main = (target / 'etc/pacman.conf').read_bytes()
            preview = json.loads(run(refresh, env=environment))
            assert preview['status'] == 'preview' and tree(target) == state
            applied = json.loads(run([*refresh, '--apply'], env=environment))
            assert applied['status'] == 'refreshed' and applied['config_changed'] and applied['keyring_may_have_changed']
            assert not applied['local_signing_requested'] and not applied['packages_installed'] and applied['snapshot_url'] == url
            assert (target / 'etc/pacman.conf').read_bytes() == before_main
            assert (target / E.INCLUDE.lstrip('/')).read_bytes() == E.config(url, old_key, E.sha(renewed_input.read_bytes()))
            checked = run(verify).decode()
            assert '[GNUPG:] VALIDSIG ' in checked and any('[GNUPG:] '+token in checked for token in ('TRUST_FULLY', 'TRUST_ULTIMATE'))
            state = tree(target)
            stale = subprocess.run(list(map(str, [*refresh, '--apply'])), capture_output=True, timeout=90, env=environment)
            assert stale.returncode == 1 and not json.loads(stale.stdout)['keyring_may_have_changed'] and tree(target) == state
            original_input.write_bytes(renewed_input.read_bytes())
            state = tree(target)
            refresh[refresh.index('--expected-current-certificate-sha256')+1] = E.sha(renewed_input.read_bytes())
            unchanged = json.loads(run([*refresh, '--apply'], env=environment))
            assert unchanged['status'] == 'unchanged' and not unchanged['config_changed'] and not unchanged['keyring_may_have_changed']
            assert tree(target) == state
            assert tree(moved) == inventory and not list(moved.rglob('__pycache__'))
            foreign = moved / 'usr/share/foreign-user-file';foreign.write_text('preserved\n')
            for name in inventory:(moved / name).unlink()
            assert tree(moved) == {'usr/share/foreign-user-file':b'preserved\n'}
            return dict(status='PASS_HOST_SYNTHETIC_PACKAGE_ONLY', payload_files=len(inventory), runtime_files=10,
                        moved_prefix=True, source_trees_hidden=True, python_environment_isolated=True,
                        network_namespace='loopback-only', zstd_package_and_declared_sources_verified=True,
                        signed_transition_preview='PASS', tamper_refusal='PASS', revocation_preview='PASS',
                        nonrevoking_certificate_refused='PASS', mapped_root_preview=True, earlier_previews_state_unchanged=True, certificate_refresh_preview='PASS',
                        certificate_refresh_apply='PASS', refreshed_signature_trusted='PASS', stale_refresh_CAS_refused='PASS',
                        refreshed_noop='PASS', global_configuration_preserved=True,
                        removal='EXACT_PAYLOAD_INVERSE_FOREIGN_CONTENT_PRESERVED',
                        native_arm_build='NOT_RUN', alpm_installation='NOT_RUN', supported_m2='NOT_RUN')
        finally:
            if 'ring' in locals():
                run(['/usr/bin/unshare', '--user', '--map-root-user', '--', 'gpgconf', '--homedir', ring, '--kill', 'all'])
            run(['gpgconf', '--homedir', next_home, '--kill', 'all'])
            run(['gpgconf', '--homedir', revoked_home, '--kill', 'all'])
            case.doCleanups()
            fixture.ReleaseTests.tearDownClass()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe-root', type=Path, required=True)
    parser.add_argument('--srcdir', type=Path, required=True)
    parser.add_argument('--hide-checkout', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(check(args.recipe_root.resolve(), args.srcdir.resolve(), args.hide_checkout.resolve()), sort_keys=True))
