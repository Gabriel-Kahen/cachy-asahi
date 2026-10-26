#!/usr/bin/env python3
"""Produce the held signed initial587 cache; never start an installer or upgrade."""
import argparse
import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import uuid

PREPARATION = '93bc9bfac7343ee3b443ae3332c0942ed1ba5b55'
EXPECTED = '2198942a546f4714587c810fe174d4457121960f3a7b1dbaa276e9f970f322c7'
BUILDER = 'cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
MAX_ARCHIVE = 256 * 1024**2
MAX_TOTAL = 4 * 1024**3
SAFE = re.compile(r'[A-Za-z0-9._+@:~-]{1,255}')


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def ordinary(path, directory=False):
    path = Path(path)
    need(path.is_absolute() and not path.is_symlink(), 'absolute ordinary input required')
    need(path.is_dir() if directory else path.is_file(), 'missing ordinary input')
    resolved = path.resolve(strict=True)
    need(',' not in str(resolved) and '\n' not in str(resolved), 'unsafe mounted input')
    return resolved


def load(path):
    name = 'installer587_composition_' + uuid.uuid4().hex
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


def preparation_prefix(api, path):
    """Keep the held preparation body, excluding its entire actor/volume tail.

    Exact named AST boundary must remain unique. The caller and this extracted
    prefix digest are retained so a changed preparation cannot pass unnoticed.
    This is source execution, equivalent to importing the held caller; no input
    manifest or package content supplies executable expressions.
    """
    tree = ast.parse(path.read_text())
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'compose']
    need(len(functions) == 1, 'one held compose function required')
    function = copy.deepcopy(functions[0])
    boundary = ast.parse("footprint = module('composition_volume_owner', HERE / 'footprint.py')").body[0]
    points = [i for i, node in enumerate(function.body)
              if ast.dump(node, include_attributes=False) == ast.dump(boundary, include_attributes=False)]
    need(len(points) == 1, 'held pre-volume preparation boundary changed')
    function.body = function.body[:points[0]]
    body = ast.dump(ast.Module(body=function.body, type_ignores=[]), include_attributes=False)
    need(not any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == 'container_args'
                 for n in ast.walk(function)), 'container actor entered preparation prefix')
    function.body += ast.parse("return {'inputs': inputs, 'plan': plan, 'image': image, 'checkpoint_sha': checkpoint_sha}").body
    function.name = 'prepare_only'
    module = ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))
    exec(compile(module, str(path) + ':pre-volume-prefix', 'exec'), api.__dict__)
    return api.prepare_only, hashlib.sha256(body.encode()).hexdigest()


def inventory(rows):
    names = [r['name'] for r in rows]
    need(len(set(names)) == len(names), 'duplicate package name')
    return ''.join(f"{r['name']} {r['version']}\n" for r in sorted(rows, key=lambda row: row['name'])).encode()


def selected_rows(base, additions, lock):
    """Only the held 573 upstream + 14 additions may define initial587."""
    need(len(base) == len({r['name'] for r in base}) == 574, 'exact574 base required')
    need(len(additions) == len({r['name'] for r in additions}) == 14, 'exact14 additions required')
    rows = [r for r in base if r['name'] != 'libfdk-aac']
    need(len(rows) == 573, 'only upstream libfdk-aac is excluded')
    rows += additions
    need(len(rows) == 587 and inventory(rows) == lock, 'initial587 package set differs from expected lock')
    need(hashlib.sha256(lock).hexdigest() == EXPECTED, 'initial587 lock pin differs')
    versions = {r['name']: r['version'] for r in rows}
    need(versions['cachy-asahi-update'] == '4.4.2-2' and versions['cachy-asahi-setup'] == '0.1.0-3',
         'initial updater2/setup3 checkpoint required')
    return rows


def checked_copy(source, target, digest, size, maximum=MAX_ARCHIVE):
    need(source.is_file() and not source.is_symlink(), 'ordinary cache file required')
    need(type(size) is int and 0 <= size <= maximum, 'cache file exceeds bound')
    need(source.stat().st_size == size and sha(source) == digest, 'cache input hash/size mismatch')
    need(not target.exists() and not target.is_symlink(), 'fresh export target required')
    shutil.copyfile(source, target)
    need(target.stat().st_size == size and sha(target) == digest, 'export copy hash/size mismatch')
    target.chmod(0o444)


def valid_signer(status, expected):
    need(re.fullmatch(r'[0-9A-F]{40}', expected) is not None, 'invalid signer fingerprint')
    records = [line.split() for line in status.splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
    # VALIDSIG may name a signing subkey; primary fingerprint is the final field.
    need(len(records) == 1 and len(records[0]) >= 12, 'one complete VALIDSIG required')
    need(expected in (records[0][2], records[0][-1]), 'signature signer differs')
    denied = ('BADSIG', 'ERRSIG', 'REVKEYSIG', 'EXPKEYSIG', 'EXPSIG', 'KEYREVOKED')
    need(not any('[GNUPG:] ' + token + ' ' in status for token in denied), 'signature status rejected')


class PublicVerifier:
    """A new public-only home, disjoint from the producer's TEST secret key."""
    def __init__(self, home, keys):
        home.mkdir(mode=0o700)
        self.home = home
        self.argv = ['gpg', '--batch', '--no-options', '--homedir', str(home),
                     '--no-auto-key-retrieve', '--auto-key-locate', 'clear']
        subprocess.run(self.argv + ['--import', *map(str, keys)], check=True,
                       capture_output=True, timeout=30)

    def __call__(self, archive, signature, signer):
        result = subprocess.run(self.argv + ['--status-fd=1', '--verify', str(signature), str(archive)],
                                check=True, capture_output=True, text=True, timeout=30)
        valid_signer(result.stdout, signer)

    def close(self):
        subprocess.run(['gpgconf', '--homedir', str(self.home), '--kill', 'all'],
                       check=True, capture_output=True, timeout=15)
        shutil.rmtree(self.home)


def export_ready(raw, ready, held, base_input, preparation, verifier_factory=PublicVerifier):
    inputs, plan = held['inputs'], held['plan']
    lock = (inputs / 'expected-installed.lock').read_bytes()
    rows = selected_rows(base_input['packages'], plan['packages'], lock)
    need(held['checkpoint_sha'] == EXPECTED, 'prepared checkpoint differs')
    projects = {p['name']: p for p in plan['projects']}
    need(len(projects) == 10 and set(projects) <= {r['name'] for r in plan['packages']}, 'exact10 project maps required')
    upstream = base_input['signer_fingerprint']
    need(upstream == plan['signer_fingerprint'], 'upstream signer roles differ')
    test = plan['test_signer_fingerprint']
    need(test != upstream, 'TEST and upstream keys must differ')
    ready.mkdir(mode=0o700)
    for name in ('packages', 'keys'):
        (ready / name).mkdir(mode=0o700)
    keys = []
    for source, name in ((inputs / 'archlinuxarm.gpg', 'archlinuxarm.gpg'), (inputs / 'TEST-public.asc', 'TEST-public.asc')):
        digest, size = sha(source), source.stat().st_size
        need(0 < size <= 1024**2, 'bounded nonempty public key required')
        expected = next((r for r in base_input['keyring_files'] if r['filename'] == name), None)
        if name == 'archlinuxarm.gpg':
            need(expected is not None and (digest, size) == (expected['sha256'], expected['size']), 'ALARM keyring pin differs')
        target = ready / 'keys' / name
        checked_copy(source, target, digest, size, 1024**2)
        keys.append({'path': 'keys/' + name, 'sha256': digest, 'size': size})
    checked_copy(inputs / 'expected-installed.lock', ready / 'expected-installed.lock', EXPECTED, len(lock), 1024**2)
    builder_lock = raw / 'desktop574/installed-packages.lock'
    need(builder_lock.read_bytes() == inventory(base_input['packages']), 'actual574 builder inventory differs')
    builder_size = builder_lock.stat().st_size
    checked_copy(builder_lock, ready / 'builder-packages.lock', BUILDER, builder_size, 1024**2)
    result, total = [], 0
    verifier = verifier_factory(raw / 'export-public-verifier', [ready / k['path'] for k in keys])
    try:
        for row in sorted(rows, key=lambda item: item['name']):
            name = row['filename']
            need(SAFE.fullmatch(name) is not None and '.pkg.tar.' in name, 'unsafe package filename')
            total += row['size']
            need(total <= MAX_TOTAL, 'compressed cache total exceeds 4GiB')
            parent = inputs if row in plan['packages'] else raw / 'desktop574/context/deps'
            archive, signature = ready / 'packages' / name, ready / 'packages' / (name + '.sig')
            checked_copy(parent / name, archive, row['sha256'], row['size'])
            checked_copy(parent / (name + '.sig'), signature, row['signature_sha256'], row['signature_size'], 1024**2)
            signer = test if row['name'] in projects else upstream
            verifier(archive, signature, signer)
            result.append({key: row[key] for key in ('name', 'version', 'sha256', 'size', 'signature_sha256', 'signature_size')} |
                          {'archive': 'packages/' + name, 'signature': 'packages/' + name + '.sig', 'signer': signer})
    finally:
        verifier.close()
    preparation = dict(preparation, signer_roles={'upstream_ALARM': upstream, 'ephemeral_TEST': test},
                       archive_count=587, compressed_archive_bytes=total,
                       export_authentication='PASS-each-signature-exact-role',
                       export_scope='public-package-cache-and-contracts-only')
    manifest = {'schema_version': 1, 'status': 'READY_SIGNED_INITIAL587',
                'expected_lock': {'path': 'expected-installed.lock', 'sha256': EXPECTED},
                'builder_lock': {'path': 'builder-packages.lock', 'sha256': BUILDER, 'size': builder_size},
                'packages': result, 'keyrings': keys, 'projects': plan['projects'], 'preparation': preparation}
    save(ready / 'manifest.json', manifest)
    (ready / 'manifest.json').chmod(0o444)
    for name in ('packages', 'keys'):
        (ready / name).chmod(0o555)
    # The ready directory stays owner-writable for coordinator's profile output;
    # archives/keys and manifest are sealed ordinary files under an owned parent.
    return ready


def revision(path):
    return subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True, timeout=15).strip()


def prepare(args):
    need(platform.machine() == 'aarch64' and os.getuid() != 0, 'native aarch64 nonroot producer required')
    for name in ('code', 'preparation_source', 'product', 'updater', 'desktop', 'updater_v2_source',
                 'native', 'fdk', 'cache', 'setup4_pair'):
        setattr(args, name, ordinary(getattr(args, name), directory=True))
    need(re.fullmatch('[0-9a-f]{40}', args.code_revision) is not None and revision(args.code) == args.code_revision,
         'held code revision differs')
    need(revision(args.preparation_source) == PREPARATION, 'held preparation revision differs')
    caller = args.code / 'scripts/ci/full-root-upgrade-caller/run.py'
    api = load(caller)
    need(api.PREPARATION_SOURCE == PREPARATION, 'caller preparation contract differs')
    for name, expected in dict(api.SOURCES, updater_v2_source=api.UPDATER_V2).items():
        need(revision(getattr(args, name)) == expected, 'held ' + name + ' revision differs')
    output = Path(args.output)
    need(output.is_absolute() and output.parent == Path('/tmp') and not output.exists() and not output.is_symlink(),
         'fresh owned /tmp output required')
    core_image = (args.native / 'image-id').read_text().strip()
    need(re.fullmatch(r'sha256:[0-9a-f]{64}', core_image), 'borrowed core image receipt required')
    before = subprocess.check_output(['docker', 'image', 'ls', '--no-trunc', '--quiet'], text=True, timeout=30).splitlines()
    need(len(before) <= 10000 and all(re.fullmatch(r'sha256:[0-9a-f]{64}', image) for image in before),
         'bounded initial image ownership observation required')
    output.mkdir(mode=0o700)
    args.output = output
    raw, public = output / 'private', output / 'public'
    raw.mkdir(mode=0o700); public.mkdir()
    save(output / 'producer-owner.json', {'schema_version': 1, 'token': uuid.uuid4().hex,
         'core_image': core_image, 'images_preexisting': sorted(set(before)),
         'preparation_source': str(args.preparation_source)})
    result = {'status': 'FAIL', 'phase': 'preparation-start', 'installer': 'NOT RUN', 'upgrade': 'NOT RUN'}
    try:
        api.HERE = args.preparation_source / 'scripts/ci/full-development-composition'
        prefix, prefix_sha = preparation_prefix(api, caller)
        held = prefix(args, raw, public, result)
        need(re.fullmatch(r'sha256:[0-9a-f]{64}', held['image']) is not None, 'exact prepared image ID required')
        image_path = raw / 'desktop574/image-id'
        need(image_path.read_text().strip() == held['image'], 'prepared image receipt differs')
        preparation = {'sources': dict(api.SOURCES, updater_v2=api.UPDATER_V2, preparation=PREPARATION, code=args.code_revision),
                       'caller_sha256': sha(caller), 'compose_prefix_ast_sha256': prefix_sha,
                       'expected_inventory_sha256': EXPECTED, 'base_inventory_sha256': api.FULL,
                       'image_id': held['image'], 'image_id_path': str(image_path),
                       'package_signatures': 'verified-each-exact-signer',
                       'base_receipt': json.loads((raw / 'desktop574/report.json').read_text()),
                       'dependency_receipt': json.loads((raw / 'dependency-audit/acquisition.json').read_text()),
                       'updater_v2_receipt': json.loads((raw / 'updater-v2-summary.json').read_text()),
                       'setup4': 'retained-input-only-not-installed', 'installer': 'NOT RUN', 'upgrade': 'NOT RUN'}
        result['phase'] = 'authenticated-initial587-cache-export'
        ready = export_ready(raw, raw / 'ready', held,
            json.loads((args.desktop / 'scripts/ci/maintained-desktop574-inputs.json').read_text()), preparation)
        result.update(status='READY_SIGNED_INITIAL587', phase='export-completed', ready=str(ready),
                      manifest_sha256=sha(ready / 'manifest.json'), owned_resources='RETAINED-UNTIL-VM-FINISHES')
        return ready
    except BaseException as error:
        result.update(error_type=type(error).__name__, error=str(error)[:1024])
        raise
    finally:
        save(public / 'producer.json', result)


def cleanup(output):
    """Only producer-owned keys, new image IDs and private files; no VM ownership."""
    output = ordinary(output, directory=True)
    need(output.parent == Path('/tmp'), 'owned /tmp output required')
    owner = json.loads((output / 'producer-owner.json').read_text())
    need(owner['schema_version'] == 1 and re.fullmatch('[0-9a-f]{32}', owner['token']), 'producer ownership receipt required')
    existing = owner['images_preexisting']
    need(type(existing) is list and len(existing) <= 10000 and
         all(re.fullmatch(r'sha256:[0-9a-f]{64}', image) for image in existing), 'initial image ownership receipt required')
    raw = output / 'private'
    failures, removed = [], set()
    for relative in ('test-signing', 'updater/native/gpg', 'updater-v2/updater/native/gpg', 'export-public-verifier'):
        home = raw / relative
        if home.exists():
            try:
                subprocess.run(['gpgconf', '--homedir', str(home), '--kill', 'all'], check=True, capture_output=True, timeout=15)
            except (OSError, subprocess.SubprocessError):
                failures.append('owned-gpg:' + relative)
    for relative in ('updater/native/image-id', 'desktop574/image-id', 'updater-v2/updater/native/image-id'):
        path = raw / relative
        if not path.exists():
            continue
        try:
            need(path.is_file() and not path.is_symlink(), 'ordinary owned image receipt required')
            image = path.read_text().strip()
            need(re.fullmatch(r'sha256:[0-9a-f]{64}', image) and image != owner['core_image'], 'borrowed core image protected')
            if image in removed or image in existing:
                continue
            subprocess.run(['docker', 'image', 'rm', '--no-prune', image], check=True, capture_output=True, timeout=30)
            observed = subprocess.run(['docker', 'image', 'inspect', image], capture_output=True, timeout=20)
            need(observed.returncode != 0 and b'No such image' in observed.stderr, 'owned image absence not established')
            removed.add(image)
        except (OSError, ValueError, subprocess.SubprocessError):
            failures.append('owned-image:' + relative)
    if not failures and raw.exists():
        # Sealed cache directories need owner write permission for scoped removal.
        for path in (raw / 'ready/packages', raw / 'ready/keys'):
            if path.is_dir() and not path.is_symlink():
                path.chmod(0o700)
        shutil.rmtree(raw)
    receipt = {'status': 'FAIL' if failures else 'PASS', 'failures': failures,
               'scope': 'producer-owned new builder images, key agents and private preparation/export files',
               'vm_cleanup': 'NOT OWNED', 'source_cache': 'BORROWED-NOT-REMOVED',
               'preexisting_images': 'BORROWED-NOT-REMOVED'}
    save(output / 'public/producer-cleanup.json', receipt)
    need(not failures, 'producer cleanup failed: ' + ','.join(failures))
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    preparation = sub.add_parser('prepare')
    for name in ('code', 'preparation-source', 'product', 'updater', 'desktop', 'updater-v2-source',
                 'native', 'fdk', 'cache', 'setup4-pair', 'output'):
        preparation.add_argument('--' + name, required=True, type=Path)
    preparation.add_argument('--code-revision', required=True)
    retirement = sub.add_parser('cleanup')
    retirement.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.action == 'prepare':
        print(prepare(args))
    else:
        print(json.dumps(cleanup(args.output), sort_keys=True))


if __name__ == '__main__':
    main()
