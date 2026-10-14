"""Trusted same-job Root observer → freeze → materialize → existing P0 pipeline."""
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import stat
import sys
import time
import types

RESOURCE_ROWS = {
    'scripts/ci/root-administration/p0_source_freeze.py': {
        'bytes': 23683, 'mode': 0o644, 'sha256': '6090d96cfea26e01bfb8f401e281a12ec224b102d564c228bda92f6c59cb2399'},
    'scripts/ci/root-administration/p0_materializer.py': {
        'bytes': 24250, 'mode': 0o644, 'sha256': 'f5efc5ca4a178cce8165337a925518feadb93922787fc867813d79ecc0b6e9cc'},
}
DRIVER = 'scripts/ci/development/p0_ci.py'
WF = '.github/workflows/native-arm-p0.yml'
QUARANTINE = []
ANCHOR = '_root_p0_admin_lifetime'


def need(value, code):
    if not value:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def live(end):
    need(type(end) in (int, float) and math.isfinite(end) and time.monotonic() < end, 'original-end')


def identity(node):
    return tuple(getattr(node, name) for name in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid',
                 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def merge(first, error):
    target = error if first is None else first
    target.__dict__['native_preflight_cleanup_uncertain'] = True
    if isinstance(error, KeyboardInterrupt) or error.__dict__.get('native_preflight_cancelled') is True:
        target.__dict__['native_preflight_cancelled'] = True
    return target


def read(path, end, *, native=False):
    live(end); before = path.lstat(); parent = identity(path.parent.lstat())
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= 64 * 1024**2
         and stat.S_IMODE(before.st_mode) == (0o755 if native else 0o644)
         and (not native or before.st_uid == before.st_gid == 0), 'Root-file-shape')
    fd = None; held = None; first = None; raw = None; opening = False
    try:
        opening = True; fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        candidate = identity(os.fstat(fd)); need(candidate == identity(before), 'Root-file-replaced'); held = candidate
        chunks = []; total = 0
        while True:
            live(end); part = os.read(fd, 65536)
            if not part:
                break
            total += len(part); need(total <= 64 * 1024**2, 'Root-file-cap'); chunks.append(part)
        raw = b''.join(chunks)
        need(len(raw) == before.st_size and identity(os.fstat(fd)) == held and identity(path.lstat()) == held
             and identity(path.parent.lstat()) == parent, 'Root-file-drift')
    except BaseException as error:
        first = error
        if isinstance(error, KeyboardInterrupt):
            first.__dict__['native_preflight_cancelled'] = True
        if opening and fd is None:
            first = merge(first, error)
    finally:
        if fd is not None:
            try:
                need(held is not None and identity(os.fstat(fd)) == held, 'Root-close-custody')
            except BaseException as error:
                QUARANTINE.append(fd); first = merge(first, error)
            else:
                try:
                    os.close(fd)
                except BaseException as error:
                    first = merge(first, error)
    if first is not None:
        raise first
    live(end)
    return raw, {'bytes': len(raw), 'mode': stat.S_IMODE(before.st_mode), 'sha256': digest(raw)}


def observe_runtime(end):
    """Root-selected Source policy; metadata only, no execution or socket connect."""
    need(sys.platform == 'linux' and platform.machine() == 'aarch64', 'native-Linux-ARM')
    rows = {}
    for role, path in (('git', '/usr/bin/git'), ('docker', '/usr/bin/docker'), ('gpg', '/usr/bin/gpg')):
        raw, row = read(Path(path), end, native=True)
        need(len(raw) >= 64 and raw[:7] == b'\x7fELF\x02\x01\x01'
             and int.from_bytes(raw[16:18], 'little') in (2, 3)
             and int.from_bytes(raw[18:20], 'little') == 183, 'native-AARCH64-ELF')
        rows[role] = row
    live(end); path = Path('/run/docker.sock'); parent = identity(path.parent.lstat())
    before = path.lstat(); node = identity(before)
    need(stat.S_ISSOCK(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
         and identity(path.lstat()) == node and identity(path.parent.lstat()) == parent, 'Root-socket-identity')
    live(end)
    return {'rows': rows, 'socket_identity': list(node[:6])}


def capture_four(environment):
    captured = {key: environment.pop(key) for key in tuple(environment) if key.startswith('CACHY_OLD_FOUR_')}
    expected = {'CACHY_OLD_FOUR_SCHEMA', 'CACHY_OLD_FOUR_SOURCE_EPOCH'}
    for tag, count in (('JBIGKIT', 2), ('JBIGKIT_SIG', 1), ('LIBTIFF', 15), ('LIBTIFF_SIG', 1)):
        expected.update('CACHY_OLD_FOUR_' + tag + '_' + str(index).zfill(2) for index in range(1, count + 1))
    need(set(captured) == expected and captured['CACHY_OLD_FOUR_SCHEMA'] == '1'
         and captured['CACHY_OLD_FOUR_SOURCE_EPOCH'] == '1791748800', 'mandatory19-and-schema')
    return captured


def load_resource(root, path, wanted, proof, end, name):
    need(type(wanted) is dict and set(wanted) == {'bytes', 'mode', 'sha256'} and wanted['mode'] == 0o644
         and proof['rows'].get(path) == wanted, 'Root-resource-provision')
    raw, row = read(root / path, end)
    need(row == wanted and name not in sys.modules, 'Root-resource-body')
    module = types.ModuleType(name); module.__file__ = str(root / path)
    sys.modules[name] = module
    # This anchor is resource custody only; it never grants permission.
    sys.__dict__[ANCHOR].append(module)
    exec(compile(raw, module.__file__, 'exec', dont_inherit=True), module.__dict__)
    return module


def require_committed_packet(freezer, git, tree, root, commit, frozen, end):
    """Metadata lock is excluded from Source269, but must be committed and exact."""
    entries = git.entries(root, commit, [freezer.LOCK], end)
    need(set(entries) == {freezer.LOCK} and entries[freezer.LOCK]['mode'] == 0o644, 'committed269-lock-required')
    item = entries[freezer.LOCK]; raw = git.blob(root, item['oid'], freezer.FILE_LIMIT, end)
    need(hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == item['oid']
         and raw == frozen['packet_raw'], 'committed269-lock-mismatch')
    physical, mode = tree.read(root / freezer.LOCK, freezer.FILE_LIMIT, end)
    need(physical == raw and mode == 0o644, 'physical269-lock-mismatch')


def run(*, entry, outer_end, root, scratch, cache, proof_raw, proof_sha256, preparation_raw,
        preparation_sha256, P0_raw, P0_sha256, review_raw, review_sha256, environment):
    need(type(entry) in (int, float) and math.isfinite(entry) and entry <= time.monotonic()
         and type(outer_end) in (int, float) and math.isfinite(outer_end), 'original-entry')
    end = min(entry + 60, outer_end - 90); live(end)
    captured = capture_four(environment)  # Before helper/provider/project code.
    first = None; result = None
    try:
        need(not QUARANTINE and ANCHOR not in sys.__dict__, 'one-shot-Root-administration')
        root = Path(root); scratch = Path(scratch); cache = Path(cache)
        need(root == Path.cwd().resolve() and scratch.is_absolute() and '..' not in scratch.parts
             and not scratch.is_relative_to(root) and not scratch.exists() and not scratch.is_symlink(), 'Root-private-path')
        expected = environment.get('EXPECTED_SOURCE_COMMIT')
        need(type(expected) is str and re.fullmatch('[0-9a-f]{40}', expected) and expected == environment.get('GITHUB_SHA')
             == environment.get('GITHUB_WORKFLOW_SHA') and environment.get('GITHUB_REPOSITORY') == 'Gabriel-Kahen/cachy-asahi'
             and environment.get('GITHUB_WORKFLOW_REF') == 'Gabriel-Kahen/cachy-asahi/' + WF
             + '@refs/heads/codex/signer-native-runtime-v1', 'Root-job-Source')
        need(type(proof_raw) is bytes and digest(proof_raw) == proof_sha256, 'Root-proof-pin')
        proof = json.loads(proof_raw)
        need(proof.get('Source') == proof.get('remote') == expected and sum(key in proof for key in ('rows', 'files')) == 1,
             'Root-proof-Source')
        proof_rows = proof['rows'] if 'rows' in proof else proof['files']
        need(type(proof_rows) is dict, 'Root-proof-row-table')
        proof = {'Source': expected, 'remote': expected, 'rows': proof_rows}
        for raw, wanted in ((preparation_raw, preparation_sha256), (P0_raw, P0_sha256), (review_raw, review_sha256)):
            need(type(raw) is bytes and digest(raw) == wanted and re.fullmatch('[0-9a-f]{64}', wanted), 'Root-private-input-pin')
        # Root explicitly selected this observer policy. Its observed hashes are
        # passed privately to a separately pinned materializer for independent reread.
        observation = observe_runtime(end)
        sys.__dict__[ANCHOR] = []
        freezer = load_resource(root, 'scripts/ci/root-administration/p0_source_freeze.py',
            RESOURCE_ROWS['scripts/ci/root-administration/p0_source_freeze.py'], proof, end, 'root_p0_source_freeze')
        materializer = load_resource(root, 'scripts/ci/root-administration/p0_materializer.py',
            RESOURCE_ROWS['scripts/ci/root-administration/p0_materializer.py'], proof, end, 'root_p0_materializer')
        git = freezer.ReadOnlyGit('/usr/bin/git', observation['rows']['git']['sha256'])
        tree = freezer.CheckoutBytes()
        need(freezer.REQUIRED_PUBLIC <= proof['rows'].keys(), 'Root-publication-required')
        projected = {'Source': expected, 'remote': expected, 'rows': {name: proof['rows'][name] for name in sorted(freezer.REQUIRED_PUBLIC)}}
        frozen = freezer.freeze_source(checkout=root, source_commit=expected, publication_raw=encoded(projected),
            publication_sha256=digest(encoded(projected)), endpoint=end, git=git, tree=tree, entry=entry)
        require_committed_packet(freezer, git, tree, root, expected, frozen, end)
        live(end); scratch.mkdir(mode=0o700)
        node = scratch.lstat(); need(stat.S_ISDIR(node.st_mode) and node.st_uid == os.geteuid()
             and stat.S_IMODE(node.st_mode) == 0o700, 'Root-owned-private-directory')
        selection = {'schema_version': 1, 'purpose': 'Root-selected-post-adoption-P0-materialization',
            'source_commit': expected, 'recipe_source_commit': environment['ROOT_RECIPE_SOURCE_COMMIT'],
            'packet_sha256': frozen['packet_sha256'], 'publication_sha256': frozen['publication_sha256'],
            'preparation_template_sha256': preparation_sha256, 'P0_template_sha256': P0_sha256,
            'source_review_sha256': review_sha256, 'runtime_rows': {role: observation['rows'][role] for role in ('docker', 'gpg')},
            'socket_identity': observation['socket_identity'], 'source_rows': frozen['source_rows'],
            'materializer_row': RESOURCE_ROWS['scripts/ci/root-administration/p0_materializer.py']}
        selection_raw = encoded(selection)
        materializer.write_private(scratch / 'Root-selection.json', selection_raw, end)
        for name, raw in (('packet.json', frozen['packet_raw']), ('publication.json', frozen['publication_raw']),
                          ('source-rows.json', frozen['source_rows_raw'])):
            materializer.write_private(scratch / name, raw, end)
        outputs = scratch / 'materialized'
        selected = materializer.root_materialize(entry=entry, outer_end=end, selection_raw=selection_raw,
            selection_sha256=digest(selection_raw), packet_raw=frozen['packet_raw'], publication_raw=frozen['publication_raw'],
            preparation_raw=preparation_raw, P0_raw=P0_raw, review_raw=review_raw, root=root, destination=outputs, environment=environment)
        env_raw, _ = materializer.file_bytes(outputs / 'pipeline-environment.json', end, private=True, limit=2 * 1024**2)
        values = materializer.decode(env_raw)
        environment.update(values)
        # Actual materialized Source/grants/runtime are already validated; Root
        # authenticates this exact selected driver before first project compile.
        wanted = frozen['source_rows'][DRIVER]; body, row = read(root / DRIVER, end)
        need(row == wanted and 'development_p0_ci' not in sys.modules, 'selected-driver-body')
        module = types.ModuleType('development_p0_ci'); module.__file__ = str(root / DRIVER)
        sys.modules[module.__name__] = module; sys.__dict__[ANCHOR].append(module)
        exec(compile(body, module.__file__, 'exec', dont_inherit=True), module.__dict__)
        need(not any(key.startswith('CACHY_OLD_FOUR_') for key in environment), 'seed-environment-drift')
        environment.update(captured)
        # No new preparation entry: all administration consumed its original frame.
        result = module.pipeline(entry=entry, outer_end=outer_end, expected_source_commit=expected,
            source_root=root, work_root=scratch.parent / ('prepared-P0-' + environment['GITHUB_RUN_ID'] + '-' + environment['GITHUB_RUN_ATTEMPT']),
            cache=cache, prep_template_raw=module.packed_template(values['PREPARATION_BUNDLE_ZLIB_B64']),
            prep_template_sha256=values['PREPARATION_BUNDLE_SHA256'])
    except BaseException as error:
        first = error
    finally:
        captured.clear()
        for key in tuple(environment):
            if key.startswith('CACHY_OLD_FOUR_'):
                environment.pop(key)
    if first is not None:
        raise first
    return result
