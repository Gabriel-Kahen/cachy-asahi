#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline recipe-bound pristine payload images; no package installation or mount.

Use plan, assemble or verify. Resume verifies an externally pinned completed
receipt; interrupted directories are retained and require a fresh destination.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import sys
import types

BASE = Path(__file__).resolve().parent
BRIDGE_SHA = '467cbb9562189b79926deb9d15d9b027d7c73d2a27ba07bc01d6740941567227'
KIND = 'cachy-asahi-pristine-payload-ext4-v1'
SIGNED_KIND = 'cachy-asahi-policy-signed-payload-ext4-v1'
SIGNED_SHA = 'fb06597a7ee68e9b3c66209e43a8b058d9d7a472a83434504936c99df2eed0f0'
INPUTS = ('selection', 'authentication', 'tool_pins', 'metadata_pins', 'root_policy')
HEX = re.compile(r'[0-9a-f]{64}\Z')
LIMIT = 8 * 1024**3
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')
STATE = dict(image='PRISTINE_ARCHIVE_PAYLOAD_ONLY', package_database='NOT_CREATED',
             trust_bootstrap='NOT_RUN', package_transaction='NOT_RUN',
             scriptlets='NOT_RUN', hooks='NOT_RUN', generated_state='NOT_CREATED',
             boot_installation='NOT_RUN', native_ARM='NOT_RUN', M2='NOT_RUN',
             source_license_closure='NOT_ACCEPTED', independent_owner_trust='NOT_ACCEPTED',
             full_release_coverage='NOT_ACCEPTED', release='NOT_ACCEPTED')


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode()


def decode(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate-json-key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite-json'))


def regular(path, maximum=LIMIT, collect=False):
    """Bounded streaming artifact read; reject special nodes, links and drift."""
    path = Path(path).absolute()
    need(path == path.resolve(), 'noncanonical-or-symlink-path')
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             0 <= before.st_size <= maximum, 'ordinary-file-bound')
        digest, count, chunks = hashlib.sha256(), 0, []
        while True:
            raw = os.read(fd, min(65536, maximum + 1 - count))
            if not raw:
                break
            count += len(raw)
            need(count <= maximum, 'file-byte-bound')
            digest.update(raw)
            if collect:
                chunks.append(raw)
        need(count == before.st_size and all(
            getattr(before, key) == getattr(os.fstat(fd), key) == getattr(path.lstat(), key)
            for key in FIELDS), 'file-drift')
        row = dict(bytes=count, sha256=digest.hexdigest(), mode=stat.S_IMODE(before.st_mode))
        return (row, b''.join(chunks)) if collect else row
    finally:
        os.close(fd)


def pinned(path, digest, maximum=1024**2):
    need(type(digest) is str and HEX.fullmatch(digest), 'sha256-required')
    row, raw = regular(path, maximum, collect=True)
    need(row['sha256'] == digest, 'input-or-source-pin')
    return raw


def load_services():
    path = BASE / 'metadata_gated_ext4.py'
    raw = pinned(path, BRIDGE_SHA)
    bridge = types.ModuleType('_release_image_bridge')
    bridge.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), bridge.__dict__)
    return bridge, bridge.sources()


def load_signed_services(selection, policy):
    path = BASE / 'signed_archive_intake.py'
    signed = types.ModuleType('_recipe_signed_archive_intake')
    signed.__file__ = str(path)
    exec(compile(pinned(path, SIGNED_SHA), str(path), 'exec'), signed.__dict__)
    services = signed.sources()
    with signed.tempfile.TemporaryDirectory(prefix='signed-recipe-plan-') as temporary:
        with services['intake'].runtime(temporary) as engine:
            source_policy = engine.load(engine.RUNTIME / 'policy.py', engine.POLICY_SHA)
            with source_policy.snapshot() as (raws, check):
                validators = source_policy.sources(raws)
                signed.policy_check(policy, signed.encoded(selection), selection,
                    validators['core'], validators['intake'], int(signed.time.time()))
                check()
    _, modules = signed.image_services()
    pins = dict(signed.PINS, signed_archive_intake=('scripts/platform/signed_archive_intake.py', SIGNED_SHA))
    return types.SimpleNamespace(run=signed.compose_image, check_sources=signed.check_sources,
                                 SOURCE_PINS=pins), modules


def prepare(recipe_path, recipe_sha256):
    raw = pinned(recipe_path, recipe_sha256)
    recipe = decode(raw)
    need(type(recipe) is dict and set(recipe) == {'schema_version', 'kind', 'epoch', 'inputs'}
         and type(recipe['schema_version']) is int and recipe['schema_version'] == 1
         and recipe['kind'] in (KIND, SIGNED_KIND), 'pristine-payload-recipe-required')
    need(type(recipe['epoch']) is int and 0 <= recipe['epoch'] <= 2147483647, 'epoch-bound')
    need(type(recipe['inputs']) is dict and set(recipe['inputs']) == set(INPUTS), 'recipe-input-closure')
    values, input_raws = {}, {}
    for name in INPUTS:
        ref = recipe['inputs'][name]
        need(type(ref) is dict and set(ref) == {'path', 'sha256'} and
             type(ref['path']) is str and Path(ref['path']).is_absolute(), 'explicit-pinned-input-required')
        input_raws[name] = pinned(ref['path'], ref['sha256'], 16*1024**2 if recipe['kind'] == SIGNED_KIND else 1024**2)
        values[name] = decode(input_raws[name])
    if recipe['kind'] == SIGNED_KIND:
        need(all(input_raws[name] == encoded(values[name]) for name in ('selection', 'authentication')),
             'canonical-signed-selection-policy-required')
        bridge, modules = load_signed_services(values['selection'], values['authentication'])
    else:
        bridge, modules = load_services()
        bridge.exact_selection(values['selection'])
    for name in ('tool_pins', 'metadata_pins'):
        need(type(values[name]) is dict and type(values[name].get('schema_version')) is int
             and values[name]['schema_version'] == 2, 'dependency-profiles-v2-required')
    need(values['root_policy'] == dict(mode=0o755, uid=0, gid=0, acl=None, xattrs={})
         and all(type(values['root_policy'][key]) is int for key in ('mode', 'uid', 'gid')),
         'unsupported-new-root-policy')
    sources = {name: dict(path=pair[0], sha256=pair[1]) for name, pair in bridge.SOURCE_PINS.items()}
    sources['bridge'] = dict(path='metadata_gated_ext4.py', sha256=BRIDGE_SHA)
    sources['release_image'] = dict(path='release_image.py', sha256=ENTRY_SHA)
    binding = dict(schema_version=1, recipe_sha256=recipe_sha256,
                   recipe_canonical_sha256=sha(encoded(recipe)), epoch=recipe['epoch'],
                   inputs={name: sha(input_raws[name]) for name in INPUTS}, sources=sources,
                   payload_state=STATE)
    return dict(recipe=recipe, raw=raw, values=values, input_raws=input_raws,
                bridge=bridge, modules=modules, binding=binding,
                binding_sha256=sha(encoded(binding)))


def plan(recipe_path, recipe_sha256):
    prepared = prepare(recipe_path, recipe_sha256)
    return dict(status='PLANNED_ONLY_NO_ARCHIVE_OR_NATIVE_ACTOR_EXECUTED',
                binding=prepared['binding'], binding_sha256=prepared['binding_sha256'])


def output_path(output):
    output = Path(output).absolute()
    need(output.parent == output.parent.resolve() and output.name not in ('', '.', '..'), 'output-parent')
    return output


def root_identity(output):
    info = output.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
         and stat.S_IMODE(info.st_mode) == 0o700, 'private-output-required')
    return info.st_dev, info.st_ino


def ledger(output):
    """Seal the entire retained artifact tree, including empty directories/modes."""
    original = root_identity(output)
    rows, total = {}, 0
    def visit(directory):
        nonlocal total
        before = directory.lstat()
        need(stat.S_ISDIR(before.st_mode), 'artifact-directory')
        for path in sorted(directory.iterdir()):
            relative = str(path.relative_to(output))
            if directory == output and relative in ('receipt.json', 'INCOMPLETE.json'):
                continue
            need(len(rows) < 100000 and len(path.parts) - len(output.parts) <= 64, 'artifact-count-depth-bound')
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                rows[relative] = dict(type='directory', mode=stat.S_IMODE(info.st_mode))
                visit(path)
            else:
                row = regular(path)
                total += row['bytes']
                need(total <= LIMIT, 'aggregate-artifact-bound')
                rows[relative] = dict(type='file', **row)
        after = directory.lstat()
        need(all(getattr(before, k) == getattr(after, k) for k in FIELDS), 'artifact-directory-drift')
    visit(output)
    need(original == root_identity(output), 'output-root-drift')
    return rows


def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def sync_directory(output):
    fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def check_prepared(prepared, recipe_path, recipe_sha256):
    need(prepare(recipe_path, recipe_sha256)['binding'] == prepared['binding'], 'recipe-or-source-drift')
    prepared['bridge'].check_sources()
    pinned(Path(__file__), ENTRY_SHA)


def readback(prepared, pipeline):
    """Use the already pinned raw reader and encoder's full inode/body comparison."""
    modules = prepared['modules']
    manifest = decode(regular(pipeline / 'staging/assembly.json', 32*1024**2, True)[1])
    meta = decode(regular(pipeline / 'inode-metadata.json', 32*1024**2, True)[1])
    result = decode(regular(pipeline / 'encoded/result.json', 32*1024**2, True)[1])
    image = regular(pipeline / 'encoded/root.ext4')
    need(all(image[key] == result['image'][key] for key in ('bytes', 'sha256')),
         'image-full-byte-binding')
    inventory = modules['encoder'].readback(pipeline / 'encoded/root.ext4')
    modules['encoder'].check_inventory(inventory, manifest['output_nodes'], meta,
        prepared['recipe']['epoch'], result['image']['uuid'], result['image']['bytes'])
    need(sha(encoded(inventory)) == result['inventory_sha256'], 'fresh-readback-inventory-binding')
    return result['image']


def verify(recipe_path, recipe_sha256, output, receipt_sha256):
    prepared = prepare(recipe_path, recipe_sha256)
    output = output_path(output)
    root_identity(output)
    need(not os.path.lexists(output / 'INCOMPLETE.json'), 'incomplete-output-cannot-resume')
    receipt = decode(pinned(output / 'receipt.json', receipt_sha256, 64*1024**2))
    need(type(receipt) is dict and receipt.get('status') == 'PASS_RECIPE_BOUND_PRISTINE_PAYLOAD_IMAGE'
         and receipt.get('binding') == prepared['binding']
         and receipt.get('binding_sha256') == prepared['binding_sha256']
         and receipt.get('payload_state') == STATE, 'receipt-recipe-binding')
    need(receipt.get('artifacts') == ledger(output), 'artifact-ledger-mismatch')
    need(receipt.get('artifacts_sha256') == sha(encoded(receipt['artifacts'])), 'artifact-ledger-binding')
    need(readback(prepared, output / 'pipeline') == receipt['image'], 'image-receipt-binding')
    check_prepared(prepared, recipe_path, recipe_sha256)
    need(receipt['artifacts'] == ledger(output), 'artifact-drift-during-verification')
    return dict(status='VERIFIED_COMPLETED_PRISTINE_PAYLOAD_IMAGE', receipt_sha256=receipt_sha256,
                binding_sha256=prepared['binding_sha256'], image=receipt['image'], actors_rerun=False,
                payload_state=STATE)


def run(recipe_path, recipe_sha256, output, resume_receipt_sha256=None):
    output = output_path(output)
    if os.path.lexists(output):
        need(resume_receipt_sha256 is not None, 'existing-output-refused-use-pinned-completed-resume')
        return verify(recipe_path, recipe_sha256, output, resume_receipt_sha256)
    need(resume_receipt_sha256 is None, 'resume-requires-existing-completed-output')
    prepared = prepare(recipe_path, recipe_sha256)
    output.mkdir(mode=0o700)
    os.chmod(output, 0o700)
    original = root_identity(output)
    write_new(output / 'INCOMPLETE.json', encoded(dict(status='INCOMPLETE_NOT_ACCEPTED',
              binding_sha256=prepared['binding_sha256'])))
    try:
        write_new(output / 'recipe.json', prepared['raw'])
        (output / 'inputs').mkdir(mode=0o700)
        for name, raw in prepared['input_raws'].items():
            write_new(output / 'inputs' / (name + '.json'), raw)
        values = prepared['values']
        result = prepared['bridge'].run(values['selection'], values['authentication'],
            values['tool_pins'], values['metadata_pins'], values['root_policy'],
            output / 'pipeline', prepared['recipe']['epoch'])
        expected_status = ('PASS_POLICY_SIGNED_DIRECT_METADATA_GATED_EXT4'
            if prepared['recipe']['kind'] == SIGNED_KIND else 'PASS_EXACT_TWO_DIRECT_METADATA_GATED_EXT4')
        need(result['status'] == expected_status
             and all(value is False for value in result['acceptance'].values()), 'pipeline-result-boundary')
        image = readback(prepared, output / 'pipeline')
        need(image == result['filesystem']['image'], 'pipeline-image-binding')
        check_prepared(prepared, recipe_path, recipe_sha256)
        need(root_identity(output) == original, 'output-root-drift')
        artifacts = ledger(output)
        receipt = dict(schema_version=1, status='PASS_RECIPE_BOUND_PRISTINE_PAYLOAD_IMAGE',
            binding=prepared['binding'], binding_sha256=prepared['binding_sha256'],
            artifacts=artifacts, artifacts_sha256=sha(encoded(artifacts)), image=image,
            pipeline_receipt_sha256=artifacts['pipeline/receipt.json']['sha256'], payload_state=STATE)
        # Flush retained leaves before committing the final externally pinnable receipt.
        for relative, row in artifacts.items():
            if row['type'] == 'file':
                fd = os.open(output / relative, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        check_prepared(prepared, recipe_path, recipe_sha256)
        need(artifacts == ledger(output), 'artifact-drift-before-publication')
        write_new(output / 'receipt.pending.json', encoded(receipt))
        for relative, row in reversed(list(artifacts.items())):
            if row['type'] == 'directory':
                sync_directory(output / relative)
        sync_directory(output)
        (output / 'INCOMPLETE.json').unlink()
        os.rename(output / 'receipt.pending.json', output / 'receipt.json')
        sync_directory(output)
        return dict(status=receipt['status'], receipt_sha256=sha(encoded(receipt)),
                    binding_sha256=prepared['binding_sha256'], image=image, payload_state=STATE)
    except BaseException as error:
        # A completed child is not a completed assembly. Retain diagnostic evidence.
        try:
            if not os.path.lexists(output / 'INCOMPLETE.json'):
                write_new(output / 'INCOMPLETE.json', encoded(dict(status='INCOMPLETE_NOT_ACCEPTED')))
            write_new(output / 'failure.json', encoded(dict(status='REFUSED_NOT_ACCEPTED',
                      error_type=type(error).__name__, error=str(error))))
        except BaseException as later:
            error.add_note('failure-record: ' + type(later).__name__ + ': ' + str(later))
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest='mode', required=True)
    for mode in ('plan', 'assemble', 'verify'):
        branch = modes.add_parser(mode)
        branch.add_argument('--recipe', required=True)
        branch.add_argument('--recipe-sha256', required=True)
        if mode != 'plan':
            branch.add_argument('--output', required=True)
        if mode == 'verify':
            branch.add_argument('--receipt-sha256', required=True)
        if mode == 'assemble':
            branch.add_argument('--resume-receipt-sha256')
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_AS, (2*1024**3, 2*1024**3))
    resource.setrlimit(resource.RLIMIT_CPU, (300, 300))
    resource.setrlimit(resource.RLIMIT_FSIZE, (256*1024**2, 256*1024**2))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    def expired(*_):
        raise TimeoutError('release-image-wall600')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(600)
    if args.mode == 'plan':
        result = plan(args.recipe, args.recipe_sha256)
    elif args.mode == 'verify':
        result = verify(args.recipe, args.recipe_sha256, args.output, args.receipt_sha256)
    else:
        result = run(args.recipe, args.recipe_sha256, args.output, args.resume_receipt_sha256)
    signal.alarm(0)
    print(json.dumps(result, sort_keys=True))


ENTRY_SHA = sha(Path(__file__).read_bytes())

if __name__ == '__main__':
    main()
