#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Create and exercise a finite, dual-signed planned release-key transition offline."""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


HERE = Path(__file__).resolve().parent
c = module('transition_comparison', HERE / 'compare_releases.py')
expiry = module('transition_expiry', HERE.parent / 'maintenance/signing_expiry.py')
r = c.r
FILES = {'transition.json', 'old-public.asc', 'new-public.asc', 'old.sig', 'new.sig'}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    path = Path(path).absolute()
    r.require('..' not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)),
              'transition path aliases/symlinks forbidden')
    return expiry.public_bytes(path)


def decode(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            r.require(key not in value, 'duplicate transition JSON field')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: r.require(False, 'nonfinite transition JSON value'))


def fields(value, keys):
    r.require(type(value) is dict and set(value) == set(keys.split()), 'unexpected/missing transition fields: ' + keys)


def gpg(home, arguments, *, signing=False):
    argv = ['/usr/bin/gpg', '--no-options', '--homedir', str(home), '--batch',
            '--auto-key-locate', 'clear', '--no-auto-key-retrieve']
    if not signing:
        argv += ['--no-autostart', '--no-auto-check-trustdb', '--no-sig-cache']
    try:
        value = subprocess.run([*argv, *map(str, arguments)], capture_output=True, timeout=60,
                               env=dict(PATH='/usr/bin:/bin', HOME=str(home), LANG='C', LC_ALL='C'))
    except (OSError, subprocess.SubprocessError) as error:
        raise r.Error('offline transition GPG unavailable or timed out') from error
    r.require(value.returncode == 0 and len(value.stdout) + len(value.stderr) <= 2 * 1024**2,
              'offline transition GPG refused input')
    return value.stdout


@contextmanager
def verifier(raw, key):
    # Inspect before import: reject secret/multiple certificates and wrong primary.
    now = int(time.time())
    report = expiry.report(expiry.inspect(raw, now), key, now, 30)
    r.require(report['signing_time_window'] == 'AVAILABLE_IN_EXPORT', 'certificate has no current signing window')
    with tempfile.TemporaryDirectory(prefix='release-transition-public-') as temporary:
        home = Path(temporary)
        certificate = home / 'certificate.asc'
        certificate.write_bytes(raw)
        gpg(home, ['--import', certificate])
        # release.py's verifier calls plain gpg; suppress all user configuration
        # and use only this freshly imported public certificate, with no agent.
        (home / 'gpg.conf').write_text('no-auto-key-retrieve\nno-auto-key-import\nauto-key-locate clear\n'
                                     'no-autostart\nno-auto-check-trustdb\nno-sig-cache\n')
        yield dict(PATH='/usr/bin:/bin', HOME=temporary, GNUPGHOME=temporary, LANG='C', LC_ALL='C')


def signature(home, data, signature_path, key):
    status = gpg(home, ['--status-fd', '1', '--verify', signature_path, data]).decode()
    valid = []
    rejected = {'KEYEXPIRED', 'SIGEXPIRED', 'EXPKEYSIG', 'EXPSIG', 'REVKEYSIG', 'KEYREVOKED',
                'BADSIG', 'ERRSIG', 'NO_PUBKEY', 'NODATA', 'FAILURE', 'ERROR'}
    for line in status.splitlines():
        words = line.split()
        if words[:1] != ['[GNUPG:]'] or len(words) < 2:
            continue
        r.require(words[1] not in rejected, 'unacceptable transition signature/key status')
        if words[1] == 'VALIDSIG':
            r.require(len(words) >= 12 and words[9] in {'8', '9', '10', '11'}, 'weak/incomplete transition signature')
            valid.append(words[-1])
    r.require(valid == [key], 'exactly one transition signature from pinned primary required')


def release_identity(path, key, env):
    manifest, spec, _, checksum = c.verified(c.directory(path), key, env)
    return dict(release_id=manifest['release_id'], release_sha256=checksum,
                repo_name=spec['repo_name'], target_arch=spec['target_arch'])


def validate(record, old_key, new_key, as_of):
    fields(record, 'schema_version purpose old_key new_key not_before not_after before after certificates')
    r.require(type(record['schema_version']) is int and record['schema_version'] == 1 and
              record['purpose'] == 'planned-release-signing-key-transition', 'transition schema/purpose mismatch')
    r.require(record['old_key'] == old_key and record['new_key'] == new_key and old_key != new_key,
              'transition requires distinct independently selected primary fingerprints')
    start, end, now = (expiry.timestamp(value) for value in (record['not_before'], record['not_after'], as_of))
    r.require(0 < end - start <= 366 * 86400 and start <= now < end, 'transition outside bounded overlap window')
    for side in ('before', 'after'):
        row = record[side]
        fields(row, 'release_id release_sha256 repo_name target_arch')
        r.valid_name(row['release_id']);r.valid_name(row['repo_name'])
        r.require(type(row['release_sha256']) is str and r.HEX.fullmatch(row['release_sha256']) and
                  row['target_arch'] == 'aarch64', 'exact ARM release hash required')
    r.require(record['before']['release_id'] != record['after']['release_id'] and
              record['before']['repo_name'] == record['after']['repo_name'], 'distinct releases in same repository required')
    fields(record['certificates'], 'old new')
    for value in record['certificates'].values():
        r.require(type(value) is str and r.HEX.fullmatch(value), 'exact public certificate SHA-256 required')


def verify(bundle, before, after, old_key, new_key, as_of, *, compare=False):
    bundle = c.directory(bundle)
    r.require({p.name for p in bundle.iterdir()} == FILES, 'unexpected/incomplete transition bundle')
    retained = {name: read(bundle / name) for name in FILES}
    record = decode(retained['transition.json'])
    old_key, new_key = r.fingerprint(old_key), r.fingerprint(new_key)
    validate(record, old_key, new_key, as_of)
    for side in ('old', 'new'):
        r.require(digest(retained[side + '-public.asc']) == record['certificates'][side], 'public certificate changed')
    with verifier(retained['old-public.asc'], old_key) as old_env, \
            verifier(retained['new-public.asc'], new_key) as new_env, \
            tempfile.TemporaryDirectory(prefix='release-transition-signatures-') as temporary:
        # GPG reads only retained copies, not mutable original bundle paths.
        copies = Path(temporary)
        for name in ('transition.json', 'old.sig', 'new.sig'):
            (copies / name).write_bytes(retained[name])
        for side, key, env in (('old', old_key, old_env), ('new', new_key, new_env)):
            signature(env['GNUPGHOME'], copies / 'transition.json', copies / (side + '.sig'), key)
        for side, path, key, env in (('before', before, old_key, old_env), ('after', after, new_key, new_env)):
            r.require(release_identity(path, key, env) == record[side], 'transition release binding mismatch: ' + side)
        result = dict(schema_version=1, status='VERIFIED_FINITE_PLANNED_KEY_TRANSITION_ONLY',
                      transition_sha256=digest(retained['transition.json']), as_of=as_of, transition=record,
                      stable_eligibility_checked=False, client_trust_changed=False,
                      current_revocation='UNKNOWN_OFFLINE_EXPORT', freshness_established=False)
        if compare:
            result['comparison'] = c.compare_releases(before, after, old_key, old_env,
                                                     after_key=new_key, after_env=new_env)
        # Verify again after comparison; no partially authenticated result escapes.
        for side, path, key, env in (('before', before, old_key, old_env), ('after', after, new_key, new_env)):
            r.require(release_identity(path, key, env) == record[side], 'release changed during transition review')
    r.require({p.name for p in bundle.iterdir()} == FILES and
              all(read(bundle / name) == raw for name, raw in retained.items()), 'transition changed during verification')
    return result


def create(args):
    old_key, new_key = r.fingerprint(args.old_key), r.fingerprint(args.new_key)
    old_raw, new_raw = read(args.old_certificate), read(args.new_certificate)
    before, after = c.directory(args.before), c.directory(args.after)
    with verifier(old_raw, old_key) as old_env, verifier(new_raw, new_key) as new_env:
        record = dict(schema_version=1, purpose='planned-release-signing-key-transition',
                      old_key=old_key, new_key=new_key, not_before=args.not_before, not_after=args.not_after,
                      before=release_identity(before, old_key, old_env), after=release_identity(after, new_key, new_env),
                      certificates=dict(old=digest(old_raw), new=digest(new_raw)))
    validate(record, old_key, new_key, args.as_of)
    output = Path(args.output).absolute()
    r.require('..' not in output.parts and not any(p.is_symlink() for p in (output, *output.parents)), 'output aliases refused')
    for path in (before, after):
        r.require(not output.is_relative_to(path), 'transition output must be outside release bundles')
    homes = []
    for home in (args.old_gpg_home, args.new_gpg_home):
        resolved = Path(home).absolute()
        r.require(not any(p.is_symlink() for p in (resolved, *resolved.parents)), 'signing home aliases refused')
        for path in (before, after, output):
            r.gpg_env(resolved, path)
        homes.append(resolved)
    output.mkdir(mode=0o700)  # Exclusive; interrupted output is incomplete and refused.
    try:
        (output / 'transition.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
        (output / 'old-public.asc').write_bytes(old_raw)
        (output / 'new-public.asc').write_bytes(new_raw)
        for side, key, home in zip(('old', 'new'), (old_key, new_key), homes):
            gpg(home, ['--local-user', key, '--digest-algo', 'SHA256', '--detach-sign',
                       '--output', output / (side + '.sig'), output / 'transition.json'], signing=True)
        return verify(output, before, after, old_key, new_key, args.as_of, compare=True)
    except BaseException:
        shutil.rmtree(output)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    for action in ('create', 'verify', 'compare'):
        command = commands.add_parser(action)
        for name in ('before', 'after', 'old-key', 'new-key', 'as-of'):
            command.add_argument('--' + name, required=True)
        if action == 'create':
            for name in ('old-certificate', 'new-certificate', 'old-gpg-home', 'new-gpg-home',
                         'not-before', 'not-after', 'output'):
                command.add_argument('--' + name, required=True)
        else:
            command.add_argument('--bundle', required=True)
    args = parser.parse_args(argv)
    result = create(args) if args.action == 'create' else verify(
        args.bundle, args.before, args.after, args.old_key, args.new_key, args.as_of, compare=args.action == 'compare')
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (r.Error, expiry.Error, OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        print('signing transition error: ' + str(error), file=sys.stderr)
        sys.exit(1)
