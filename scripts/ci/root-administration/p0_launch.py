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

DIAGNOSTIC_STAGES = {'entry': frozenset({'validate-entry'}), 'seed': frozenset({'capture-seed'}), 'selection': frozenset({'validate-selection'}), 'observation': frozenset({'observe-docker', 'observe-socket', 'validate-host', 'observe-gpg', 'observe-git'}), 'resource': frozenset({'load-freezer', 'load-materializer'}), 'freeze': frozenset({'freeze-source', 'initialize-git'}), 'packet': frozenset({'verify-committed-packet'}), 'private': frozenset({'write-selection'}), 'materializer': frozenset({'materialize-templates', 'read-environment'}), 'driver': frozenset({'load-driver'}), 'pipeline': frozenset({'run-pipeline'}), 'cleanup': frozenset({'erase-seed'}), 'UNKNOWN': frozenset({'UNKNOWN'})}
DIAGNOSTIC_CODES = {'launcher': frozenset({'Root-close-custody', 'Root-resource-body', 'physical269-lock-mismatch', 'seed-environment-drift', 'selected-driver-body', 'native-AARCH64-ELF', 'Root-proof-row-table', 'native-Linux-ARM', 'Root-file-replaced', 'Root-publication-required', 'Root-proof-pin', 'mandatory19-and-schema', 'Root-file-drift', 'original-end', 'Root-private-input-pin', 'Root-owned-private-directory', 'one-shot-Root-administration', 'Root-job-Source', 'Root-private-path', 'Root-proof-Source', 'committed269-lock-required', 'Root-socket-identity', 'original-entry', 'Root-file-cap', 'committed269-lock-mismatch', 'Root-resource-provision', 'Root-file-shape'}), 'freezer': frozenset({'original71-inputs-required', 'generic-policy-refused', 'Root-publication-row-drift', 'Root-checkout-required', 'original-entry-expired', 'regular-Source-leaf-required', 'Source-path-refused', 'close-Source-FD-drift', 'final-physical-Source-drift', 'Source-literal-refused', 'Source-map-leaf-drift', 'Root-Source-required', 'Git-read-failed', 'selector-changed-during-freeze', 'unresolved-prior-read-custody', 'virtual-metadata-drift', 'Source-map-refused', 'experiment-exporter-drift', 'held-Source-drift', 'original159-drift', 'Git-blob-identity-refused', 'physical-Git-Source-drift', 'Root-publication-Source-refused', 'recipe-map-refused', 'Root-Git-body-refused', 'final-HEAD-drift', 'original-contract-refused', 'data-write-readback-drift', 'P0-variant-drift', 'Root-publication-hash-refused', 'Source-row-refused', 'final-held-Source-drift', 'original-endpoint-required', 'fresh-data-write-required', 'unresolved-prior-Git-custody', 'owned-data-file-drift', 'Source-file-limit', 'original-entry-required', 'data-write-incomplete', 'original-endpoint-expired', 'closed-Git-read-required', 'recipe-input-drift', 'Source-selector-refused', 'checkout-HEAD-refused', 'Git-blob-mode-refused', 'fresh-data-output-required', 'Git-exact270-refused', 'Git-tree-refused', 'Root-publication-required-rows', 'original-four-recipes-required', 'metadata-contract-refused', 'owned-data-file-required', 'experiment-map-drift', 'Root-publication-table-refused', 'data-output-limit', 'publication644-required', 'Git-output-limit', 'pending-data-FD-unbound', 'Source-total-limit', 'exact269-selector-refused'}), 'materializer': frozenset({'pipeline-gpg-env-null', 'nonfinite-json', 'pipeline-publication-closure', 'Root-socket-selection', 'Root-selected-helper-code', 'distinct-purpose0', 'no-fabricated-image', 'observed-runtime-pin', 'private-write-drift', 'template-output-set', 'json-bound', 'private-write-progress', 'metadata-pin', 'held-scope', 'held-template-schema', 'json-object', 'published-job-Source', 'recipe-Source', 'independent-runtime-pin', 'packed-template-cap', 'hash-pin', 'private-write-shape', 'pipeline-owned-slot', 'Source-body-pin', 'narrow-map-join', 'docker-socket-drift', 'actual-packet269', 'file-shape', 'first-entry', 'Root-callback-slot', 'actual-adopted-Source-row', 'held-original159', 'independent-socket-selection', 'file-cap', 'runtime-row', 'Source-total', 'materializer-paths', 'original3c16', 'source-path', 'original-end', 'pipeline-P0-null-slot', 'runtime-selection', 'private-directory', 'close-custody', 'private-close-custody', 'docker-socket-shape', 'Root-input-pin', 'duplicate-key', 'Source-body-set', 'fixed-preparation-selection', 'pipeline-publication-row', 'file-replaced', 'Root-materializer-row', 'private-write-custody', 'unfilled-runtime', 'Source-row', 'unfilled-gpg', 'published-270-rows', 'private-readback', 'Root-selection', 'file-drift', 'actual-publication', 'pipeline-plan-null-slot', 'pipeline-private-env-null', 'observed-endpoint6', 'explicit-Root-review-decision', 'packet-row-join', 'pipeline-image-null-slot', 'Root-selected-data'}), 'pipeline': frozenset({'p0-json-number', 'prep-container-retirement', 'p0-publication-row', 'p0-publication-closure', 'prep-fixed-four-inputs', 'prep-source-total', 'p0-input-cap', 'p0-input-pin', 'prep-download-fd', 'p0-private-template', 'prep-private-template', 'prep-materialized-input-pin', 'prep-download-close-custody', 'prep-command-exit', 'prep-environment', 'p0-preparation-route', 'p0-output-boundary', 'p0-input-file', 'prep-job-context', 'prep-bootstrap-body', 'p0-preparation-template', 'prep-warm-cache-required', 'prep-source-owner', 'p0-preparation-origin', 'prep-container-custody', 'prep-package-retirement', 'prep-template-nonce', 'p0-publication', 'prep-cache-set', 'prep-grant-scope', 'prep-template', 'p0-template', 'p0-invocation', 'p0-frame', 'p0-environment', 'p0-source-path', 'p0-callback', 'p0-private-fresh', 'prep-publication', 'p0-original-entry', 'prep-packet-drift', 'prep-existing-timer', 'prep-override-content', 'p0-template-scope', 'prep-download-input', 'prep-download-cap', 'p0-input-replaced', 'p0-private-write-custody', 'p0-private-write-progress', 'prep-gpg-drift', 'prep-download-downgrade', 'prep-gpg-argv', 'prep-fixed-four-no-HTTPS-fallback', 'prep-P0-complete', 'p0-private-custody', 'p0-template-frame', 'prep-command-frame', 'prep-tag-custody', 'p0-input-set', 'prep-gpg-pin', 'p0-template-packages', 'p0-grant-scope', 'prep-original-entry', 'prep-callback', 'p0-bootstrap-custody', 'prep-docker-argv', 'p0-private-final-custody', 'prep-owned-tag', 'p0-source-row', 'prep-download-file', 'prep-fixed-four-cache-custody', 'p0-input-drift', 'prep-complete', 'p0-runtime-selection', 'p0-input-ancestor', 'p0-private-created', 'p0-duplicate-key', 'prep-host-ARM', 'prep-selection', 'prep-fixed-four-bytes', 'p0-private-close-custody', 'prep-fixed-four-readback', 'prep-gpg-close-custody', 'template-packed-cap', 'prep-view', 'p0-bootstrap-body', 'prep-download-response-custody', 'prep-fixed-four-cache-drift', 'prep-fixed-four-seed-no-URLs', 'prep-output-custody', 'prep-materialized-input-readback', 'prep-template-job', 'prep-download-domain', 'p0-prepared-image', 'prep-tag-retirement', 'p0-template-view', 'template-packed', 'p0-actual-packages', 'prep-publication-row', 'prep-original-frame', 'prep-registry-retirement', 'prep-warm-cache', 'prep-cache-custody', 'p0-job-context', 'p0-existing-timer', 'prep-private-fresh', 'template-decoded-cap', 'prep-gpg-operation', 'p0-bootstrap-unfilled', 'prep-download-redirect', 'p0-input-close-custody', 'prep-image-id', 'prep-publication-closure', 'p0-packet-drift', 'p0-module-collision', 'p0-sticky-cancel', 'prep-download-pin', 'prep-fixed-four-schema', 'prep-module-collision', 'p0-result', 'prep-build-outcome-unknown', 'prep-source-path', 'prep-command-retirement', 'prep-quarantine', 'p0-registry-retirement', 'prep-authority', 'prep-fixed-four-count', 'p0-original-end', 'prep-inventory-name-must-be-absent', 'prep-daemon-ARM', 'prep-tag-must-be-absent', 'prep-docker-operation', 'p0-private-cap', 'prep-docker-close-custody', 'p0-input-path', 'prep-packages', 'prep-output-drift', 'p0-actual-preparation', 'prep-fixed-four-seed-required', 'prep-fixed-four-chunk', 'prep-cache-selection', 'p0-source-total', 'prep-fixed-four-total', 'prep-runtime', 'prep-template-pin', 'p0-packages', 'p0-source-commit', 'prep-command-count', 'prep-download-progress', 'prep-download-target', 'p0-template-pin', 'prep-inputs', 'prep-inventory-container-absence', 'p0-template-job-field', 'prep-paths', 'p0-runtime-contract'})}
DIAGNOSTIC_TYPES = {'ValueError', 'TypeError', 'RuntimeError', 'OSError', 'KeyboardInterrupt', 'SystemExit', 'UNKNOWN'}


def exception_state(error):
    """Read builtin exception storage without subclass descriptors or hooks."""
    state = BaseException.__dict__['__dict__'].__get__(error)
    if type(state) is dict and all(type(key) is str for key in state):
        return state
    return None


def diagnostic(error, stage, operation, domain):
    """Pure closed facts; no error text, paths, arguments, payload or runtime rows."""
    need(stage in DIAGNOSTIC_STAGES and operation in DIAGNOSTIC_STAGES[stage] and domain in DIAGNOSTIC_CODES,
         'diagnostic-shape')
    kind = 'UNKNOWN'
    for exact, label in ((ValueError, 'ValueError'), (TypeError, 'TypeError'), (RuntimeError, 'RuntimeError'),
        (OSError, 'OSError'), (FileNotFoundError, 'OSError'), (PermissionError, 'OSError'),
        (IsADirectoryError, 'OSError'), (NotADirectoryError, 'OSError'), (BlockingIOError, 'OSError'),
        (ChildProcessError, 'OSError'), (ProcessLookupError, 'OSError'), (TimeoutError, 'OSError'),
        (ConnectionError, 'OSError'), (BrokenPipeError, 'OSError'), (ConnectionAbortedError, 'OSError'),
        (ConnectionRefusedError, 'OSError'), (ConnectionResetError, 'OSError'),
        (FileExistsError, 'OSError'), (InterruptedError, 'OSError'),
        (KeyboardInterrupt, 'KeyboardInterrupt'), (SystemExit, 'SystemExit')):
        if type(error) is exact:
            kind = label
            break
    code = 'UNKNOWN'
    if type(error) is ValueError:
        args = BaseException.__dict__['args'].__get__(error)
        if type(args) is tuple and len(args) == 1 and type(args[0]) is str and args[0] in set().union(*DIAGNOSTIC_CODES.values()):
            code = args[0]
    return {'schema_version': 1, 'stage': stage, 'operation': operation, 'exception_type': kind, 'refusal_code': code}



def attach_diagnostic(error, stage, operation, domain):
    """Never replace the primary; first closed record survives later collection."""
    try:
        state = exception_state(error)
        if type(state) is not dict or not all(type(key) is str for key in state):
            return
        old = state.get('nativeci_diagnostic')
        if type(old) is dict and all(type(key) is str for key in old) and set(old) == {'schema_version', 'stage', 'operation', 'exception_type', 'refusal_code'} and \
           type(old['schema_version']) is int and old['schema_version'] == 1 and all(type(old[key]) is str for key in ('stage', 'operation', 'exception_type', 'refusal_code')) and old['stage'] in DIAGNOSTIC_STAGES and \
           old['operation'] in DIAGNOSTIC_STAGES[old['stage']] and old['exception_type'] in DIAGNOSTIC_TYPES and \
           old['refusal_code'] in {'UNKNOWN'} | set().union(*DIAGNOSTIC_CODES.values()):
            return
        state['nativeci_diagnostic'] = diagnostic(error, stage, operation, domain)
    except BaseException as secondary:
        if type(secondary) is KeyboardInterrupt:
            try:
                state = exception_state(error)
                if state is not None:
                    state['native_preflight_cancelled'] = True
                    state['native_preflight_cleanup_uncertain'] = True
            except BaseException:
                pass



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
    try:
        return _observe_runtime(end)
    except BaseException as error:
        attach_diagnostic(error, 'observation', 'validate-host', 'launcher')
        raise


def _observe_runtime(end):
    """Root-selected Source policy; metadata only, no execution or socket connect."""
    need(sys.platform == 'linux' and platform.machine() == 'aarch64', 'native-Linux-ARM')
    rows = {}
    for role, path in (('git', '/usr/bin/git'), ('docker', '/usr/bin/docker'), ('gpg', '/usr/bin/gpg')):
        try:
            raw, row = read(Path(path), end, native=True)
            need(len(raw) >= 64 and raw[:7] == b'\x7fELF\x02\x01\x01'
             and int.from_bytes(raw[16:18], 'little') in (2, 3)
                 and int.from_bytes(raw[18:20], 'little') == 183, 'native-AARCH64-ELF')
        except BaseException as error:
            attach_diagnostic(error, 'observation', 'observe-' + role, 'launcher')
            raise
        rows[role] = row
    try:
        live(end); path = Path('/run/docker.sock'); parent = identity(path.parent.lstat())
        before = path.lstat(); node = identity(before)
        need(stat.S_ISSOCK(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
             and identity(path.lstat()) == node and identity(path.parent.lstat()) == parent, 'Root-socket-identity')
        live(end)
    except BaseException as error:
        attach_diagnostic(error, 'observation', 'observe-socket', 'launcher')
        raise
    return {'rows': rows, 'socket_identity': list(node[:6])}


def capture_four(environment):
    try:
        return _capture_four(environment)
    except BaseException as error:
        attach_diagnostic(error, 'seed', 'capture-seed', 'launcher')
        raise


def _capture_four(environment):
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


def _run(*, entry, outer_end, root, scratch, cache, proof_raw, proof_sha256, preparation_raw,
        preparation_sha256, P0_raw, P0_sha256, review_raw, review_sha256, environment):
    need(type(entry) in (int, float) and math.isfinite(entry) and entry <= time.monotonic()
         and type(outer_end) in (int, float) and math.isfinite(outer_end), 'original-entry')
    end = min(entry + 60, outer_end - 90); live(end)
    captured = capture_four(environment)  # Before helper/provider/project code.
    first = None; result = None
    stage, operation, domain = 'selection', 'validate-selection', 'launcher'
    try:
        stage, operation, domain = 'selection', 'validate-selection', 'launcher'
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
        stage, operation, domain = 'observation', 'validate-host', 'launcher'
        observation = observe_runtime(end)
        sys.__dict__[ANCHOR] = []
        stage, operation, domain = 'resource', 'load-freezer', 'launcher'
        freezer = load_resource(root, 'scripts/ci/root-administration/p0_source_freeze.py',
            RESOURCE_ROWS['scripts/ci/root-administration/p0_source_freeze.py'], proof, end, 'root_p0_source_freeze')
        stage, operation, domain = 'resource', 'load-materializer', 'launcher'
        materializer = load_resource(root, 'scripts/ci/root-administration/p0_materializer.py',
            RESOURCE_ROWS['scripts/ci/root-administration/p0_materializer.py'], proof, end, 'root_p0_materializer')
        stage, operation, domain = 'freeze', 'initialize-git', 'freezer'
        git = freezer.ReadOnlyGit('/usr/bin/git', observation['rows']['git']['sha256'])
        tree = freezer.CheckoutBytes()
        need(freezer.REQUIRED_PUBLIC <= proof['rows'].keys(), 'Root-publication-required')
        projected = {'Source': expected, 'remote': expected, 'rows': {name: proof['rows'][name] for name in sorted(freezer.REQUIRED_PUBLIC)}}
        stage, operation, domain = 'freeze', 'freeze-source', 'freezer'
        frozen = freezer.freeze_source(checkout=root, source_commit=expected, publication_raw=encoded(projected),
            publication_sha256=digest(encoded(projected)), endpoint=end, git=git, tree=tree, entry=entry)
        stage, operation, domain = 'packet', 'verify-committed-packet', 'launcher'
        require_committed_packet(freezer, git, tree, root, expected, frozen, end)
        stage, operation, domain = 'private', 'write-selection', 'materializer'
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
        stage, operation, domain = 'materializer', 'materialize-templates', 'materializer'
        selected = materializer.root_materialize(entry=entry, outer_end=end, selection_raw=selection_raw,
            selection_sha256=digest(selection_raw), packet_raw=frozen['packet_raw'], publication_raw=frozen['publication_raw'],
            preparation_raw=preparation_raw, P0_raw=P0_raw, review_raw=review_raw, root=root, destination=outputs, environment=environment)
        stage, operation, domain = 'materializer', 'read-environment', 'materializer'
        env_raw, _ = materializer.file_bytes(outputs / 'pipeline-environment.json', end, private=True, limit=2 * 1024**2)
        values = materializer.decode(env_raw)
        environment.update(values)
        # Actual materialized Source/grants/runtime are already validated; Root
        # authenticates this exact selected driver before first project compile.
        stage, operation, domain = 'driver', 'load-driver', 'launcher'
        wanted = frozen['source_rows'][DRIVER]; body, row = read(root / DRIVER, end)
        need(row == wanted and 'development_p0_ci' not in sys.modules, 'selected-driver-body')
        module = types.ModuleType('development_p0_ci'); module.__file__ = str(root / DRIVER)
        sys.modules[module.__name__] = module; sys.__dict__[ANCHOR].append(module)
        exec(compile(body, module.__file__, 'exec', dont_inherit=True), module.__dict__)
        need(not any(key.startswith('CACHY_OLD_FOUR_') for key in environment), 'seed-environment-drift')
        environment.update(captured)
        # No new preparation entry: all administration consumed its original frame.
        stage, operation, domain = 'pipeline', 'run-pipeline', 'pipeline'
        result = module.pipeline(entry=entry, outer_end=outer_end, expected_source_commit=expected,
            source_root=root, work_root=scratch.parent / ('prepared-P0-' + environment['GITHUB_RUN_ID'] + '-' + environment['GITHUB_RUN_ATTEMPT']),
            cache=cache, prep_template_raw=module.packed_template(values['PREPARATION_BUNDLE_ZLIB_B64']),
            prep_template_sha256=values['PREPARATION_BUNDLE_SHA256'])
    except BaseException as error:
        first = error
        attach_diagnostic(first, stage, operation, domain)
    finally:
        try:
            captured.clear()
            for key in tuple(environment):
                if key.startswith('CACHY_OLD_FOUR_'):
                    environment.pop(key)
        except BaseException as error:
            if first is None:
                first = error
                attach_diagnostic(first, 'cleanup', 'erase-seed', 'launcher')
            first = merge(first, error)
    if first is not None:
        raise first
    return result


def run(*, entry, outer_end, root, scratch, cache, proof_raw, proof_sha256, preparation_raw,
        preparation_sha256, P0_raw, P0_sha256, review_raw, review_sha256, environment):
    try:
        return _run(entry=entry, outer_end=outer_end, root=root, scratch=scratch, cache=cache,
            proof_raw=proof_raw, proof_sha256=proof_sha256, preparation_raw=preparation_raw,
            preparation_sha256=preparation_sha256, P0_raw=P0_raw, P0_sha256=P0_sha256,
            review_raw=review_raw, review_sha256=review_sha256, environment=environment)
    except BaseException as error:
        attach_diagnostic(error, 'entry', 'validate-entry', 'launcher')
        raise
