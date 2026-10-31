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

RESOURCE_ROWS = {'scripts/ci/root-administration/p0_source_freeze.py': {'bytes': 23683, 'mode': 420, 'sha256': '6090d96cfea26e01bfb8f401e281a12ec224b102d564c228bda92f6c59cb2399'}, 'scripts/ci/root-administration/p0_materializer.py': {'bytes': 27154, 'mode': 420, 'sha256': 'f6f734f1cfed83984c48cd70ee7fdbcd3d519b484fd9e5e7120e63e371a42549'}}
DRIVER = 'scripts/ci/development/p0_ci.py'
WF = '.github/workflows/native-arm-p0.yml'
QUARANTINE = []
ANCHOR = '_root_p0_admin_lifetime'

DIAGNOSTIC_STAGES = {'entry': frozenset({'validate-entry'}), 'seed': frozenset({'capture-seed'}), 'selection': frozenset({'validate-selection'}), 'observation': frozenset({'observe-docker', 'observe-socket', 'validate-host', 'observe-gpg', 'observe-git'}), 'resource': frozenset({'load-freezer', 'load-materializer'}), 'freeze': frozenset({'freeze-source', 'initialize-git'}), 'packet': frozenset({'verify-committed-packet'}), 'private': frozenset({'write-selection'}), 'materializer': frozenset({'materialize-templates', 'read-environment'}), 'driver': frozenset({'load-driver'}), 'pipeline': frozenset({'run-pipeline', 'prepare-pipeline-arguments'}), 'cleanup': frozenset({'erase-seed'}), 'UNKNOWN': frozenset({'UNKNOWN'})}
DIAGNOSTIC_STAGES['pipeline'] = DIAGNOSTIC_STAGES['pipeline'] | frozenset(['load-preparation', 'verify-preparation-packet', 'load-preparation-sources', 'initialize-preparation', 'prepare-image', 'finish-preparation', 'materialize-P0', 'run-P0', 'run-P0-sdk-callback', 'run-P0-sdk-class_state', 'run-P0-sdk-source_graph', 'run-P0-sdk-graph_namespace', 'run-P0-sdk-graph_identity', 'run-P0-sdk-global_function', 'run-P0-sdk-graph_function', 'run-P0-sdk-namespace_source', 'run-P0-sdk-locate', 'run-P0-controller-installer', 'run-P0-controller-consumer', 'run-P0-original-main', 'run-P0-original-controller', 'run-P0-preflight-namespace', 'run-P0-preflight-live', 'run-P0-preflight-run', 'run-P0-entry-authenticate', 'run-P0-entry-run', 'run-P0-entry-projection', 'run-P0-preflight-image_handoff', 'run-P0-preflight-container_binding', 'run-P0-preflight-selection', 'run-P0-preflight-accept', 'pipeline-cleanup', 'download-input', 'download-http-error', 'download-url-error', 'download-timeout', 'supervise-child', 'supervise-child-timeout', 'check-child-outcome'])
DIAGNOSTIC_STAGES['pipeline'] = DIAGNOSTIC_STAGES['pipeline'] | {"run-P0-preflight-L" + str(line) for line in (191, 193, 194, 195, 196, 198, 199, 200, 201, 203, 207, 208, 209, 210, 211, 212, 213, 214, 217, 222, 223, 224, 225, 226, 229, 231, 232, 233, 234, 235, 236, 237, 238, 239, 251, 252, 253, 256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 286, 287, 288, 290, 291, 292, 294, 295, 297, 298, 304, 305, 306, 307, 309, 310, 311, 312, 313, 314, 315, 316, 318, 319, 321, 322, 323, 326, 328, 329, 331, 333, 334, 335, 336, 337, 339, 342, 343, 344, 345, 346, 347, 348, 349, 350, 351, 353, 354, 356, 357, 358, 359, 360, 361, 362, 363, 364, 365, 366, 367, 369, 370, 371, 373, 376, 381, 382, 385, 388, 390, 394, 395, 396, 398, 399, 402, 404, 405)}
DIAGNOSTIC_STAGES['preparation-sdk-preflight'] = ['preflight', 'decode-duplicate', 'decode-number', 'decode-bytes', 'decode-object', 'grant-pin', 'grant-schema', 'contract-pin', 'job-identifier', 'original-view', 'policy-source-pin', 'policy-fields']
DIAGNOSTIC_STAGES['P0-sdk-preflight'] = ['preflight', 'decode-duplicate', 'decode-number', 'decode-bytes', 'decode-object', 'grant-pin', 'grant-schema', 'contract-pin', 'job-identifier', 'original-view', 'policy-source-pin', 'policy-fields']
DIAGNOSTIC_CODES = {'launcher': frozenset(['Root-close-custody', 'Root-file-cap', 'Root-file-drift', 'Root-file-replaced', 'Root-file-shape', 'Root-job-Source', 'Root-owned-private-directory', 'Root-private-input-pin', 'Root-private-path', 'Root-proof-Source', 'Root-proof-pin', 'Root-proof-row-table', 'Root-publication-required', 'Root-resource-body', 'Root-resource-provision', 'Root-socket-identity', 'committed269-lock-mismatch', 'committed269-lock-required', 'mandatory19-and-schema', 'native-AARCH64-ELF', 'native-Linux-ARM', 'one-shot-Root-administration', 'original-end', 'original-entry', 'physical269-lock-mismatch', 'seed-environment-drift', 'selected-driver-body']), 'freezer': frozenset(['Git-blob-identity-refused', 'Git-blob-mode-refused', 'Git-exact270-refused', 'Git-output-limit', 'Git-read-failed', 'Git-tree-refused', 'P0-variant-drift', 'Root-Git-body-refused', 'Root-Source-required', 'Root-checkout-required', 'Root-publication-Source-refused', 'Root-publication-hash-refused', 'Root-publication-required-rows', 'Root-publication-row-drift', 'Root-publication-table-refused', 'Source-file-limit', 'Source-literal-refused', 'Source-map-leaf-drift', 'Source-map-refused', 'Source-path-refused', 'Source-row-refused', 'Source-selector-refused', 'Source-total-limit', 'checkout-HEAD-refused', 'close-Source-FD-drift', 'closed-Git-read-required', 'data-output-limit', 'data-write-incomplete', 'data-write-readback-drift', 'exact269-selector-refused', 'experiment-exporter-drift', 'experiment-map-drift', 'final-HEAD-drift', 'final-held-Source-drift', 'final-physical-Source-drift', 'fresh-data-output-required', 'fresh-data-write-required', 'generic-policy-refused', 'held-Source-drift', 'metadata-contract-refused', 'original-contract-refused', 'original-endpoint-expired', 'original-endpoint-required', 'original-entry-expired', 'original-entry-required', 'original-four-recipes-required', 'original159-drift', 'original71-inputs-required', 'owned-data-file-drift', 'owned-data-file-required', 'pending-data-FD-unbound', 'physical-Git-Source-drift', 'publication644-required', 'recipe-input-drift', 'recipe-map-refused', 'regular-Source-leaf-required', 'selector-changed-during-freeze', 'unresolved-prior-Git-custody', 'unresolved-prior-read-custody', 'virtual-metadata-drift']), 'materializer': frozenset(['Root-callback-slot', 'Root-input-pin', 'Root-materializer-row', 'Root-selected-data', 'Root-selected-helper-code', 'Root-selection', 'Root-socket-selection', 'Source-body-pin', 'Source-body-set', 'Source-row', 'Source-total', 'actual-adopted-Source-row', 'actual-packet269', 'actual-publication', 'close-custody', 'distinct-purpose0', 'docker-socket-drift', 'docker-socket-shape', 'duplicate-key', 'explicit-Root-review-decision', 'file-cap', 'file-drift', 'file-replaced', 'file-shape', 'first-entry', 'fixed-preparation-selection', 'hash-pin', 'held-original159', 'held-scope', 'held-template-schema', 'independent-runtime-pin', 'independent-socket-selection', 'json-bound', 'json-object', 'materializer-paths', 'metadata-pin', 'narrow-map-join', 'no-fabricated-image', 'nonfinite-json', 'observed-endpoint6', 'observed-runtime-pin', 'original-end', 'original3c16', 'packed-template-cap', 'packet-row-join', 'pipeline-P0-null-slot', 'pipeline-gpg-env-null', 'pipeline-image-null-slot', 'pipeline-owned-slot', 'pipeline-plan-null-slot', 'pipeline-private-env-null', 'pipeline-publication-closure', 'pipeline-publication-row', 'private-close-custody', 'private-directory', 'private-readback', 'private-write-custody', 'private-write-drift', 'private-write-progress', 'private-write-shape', 'published-270-rows', 'published-job-Source', 'recipe-Source', 'runtime-row', 'runtime-selection', 'source-path', 'template-output-set', 'unfilled-gpg', 'unfilled-runtime']), 'pipeline': frozenset(['p0-actual-packages', 'p0-actual-preparation', 'p0-bootstrap-body', 'p0-bootstrap-custody', 'p0-bootstrap-unfilled', 'p0-callback', 'p0-duplicate-key', 'p0-environment', 'p0-existing-timer', 'p0-frame', 'p0-grant-scope', 'p0-input-ancestor', 'p0-input-cap', 'p0-input-close-custody', 'p0-input-drift', 'p0-input-file', 'p0-input-path', 'p0-input-pin', 'p0-input-replaced', 'p0-input-set', 'p0-invocation', 'p0-job-context', 'p0-json-number', 'p0-module-collision', 'p0-original-end', 'p0-original-entry', 'p0-output-boundary', 'p0-packages', 'p0-packet-drift', 'p0-preparation-origin', 'p0-preparation-route', 'p0-preparation-template', 'p0-prepared-image', 'p0-private-cap', 'p0-private-close-custody', 'p0-private-created', 'p0-private-custody', 'p0-private-final-custody', 'p0-private-fresh', 'p0-private-template', 'p0-private-write-custody', 'p0-private-write-progress', 'p0-publication', 'p0-publication-closure', 'p0-publication-row', 'p0-registry-retirement', 'p0-result', 'p0-runtime-contract', 'p0-runtime-selection', 'p0-source-commit', 'p0-source-path', 'p0-source-row', 'p0-source-total', 'p0-sticky-cancel', 'p0-template', 'p0-template-frame', 'p0-template-job-field', 'p0-template-packages', 'p0-template-pin', 'p0-template-scope', 'p0-template-view', 'prep-P0-complete', 'prep-authority', 'prep-bootstrap-body', 'prep-build-outcome-unknown', 'prep-cache-custody', 'prep-cache-selection', 'prep-cache-set', 'prep-callback', 'prep-command-count', 'prep-command-exit', 'prep-command-frame', 'prep-command-retirement', 'prep-complete', 'prep-container-custody', 'prep-container-retirement', 'prep-daemon-ARM', 'prep-docker-argv', 'prep-docker-close-custody', 'prep-docker-operation', 'prep-download-cap', 'prep-download-close-custody', 'prep-download-domain', 'prep-download-downgrade', 'prep-download-fd', 'prep-download-file', 'prep-download-input', 'prep-download-pin', 'prep-download-progress', 'prep-download-redirect', 'prep-download-response-custody', 'prep-download-target', 'prep-environment', 'prep-existing-timer', 'prep-fixed-four-bytes', 'prep-fixed-four-cache-custody', 'prep-fixed-four-cache-drift', 'prep-fixed-four-chunk', 'prep-fixed-four-count', 'prep-fixed-four-inputs', 'prep-fixed-four-no-HTTPS-fallback', 'prep-fixed-four-readback', 'prep-fixed-four-schema', 'prep-fixed-four-seed-no-URLs', 'prep-fixed-four-seed-required', 'prep-fixed-four-total', 'prep-gpg-argv', 'prep-gpg-close-custody', 'prep-gpg-drift', 'prep-gpg-operation', 'prep-gpg-pin', 'prep-grant-scope', 'prep-host-ARM', 'prep-image-id', 'prep-inputs', 'prep-inventory-container-absence', 'prep-inventory-name-must-be-absent', 'prep-job-context', 'prep-materialized-input-pin', 'prep-materialized-input-readback', 'prep-module-collision', 'prep-original-entry', 'prep-original-frame', 'prep-output-custody', 'prep-output-drift', 'prep-override-content', 'prep-owned-tag', 'prep-package-retirement', 'prep-packages', 'prep-packet-drift', 'prep-paths', 'prep-private-fresh', 'prep-private-template', 'prep-publication', 'prep-publication-closure', 'prep-publication-row', 'prep-quarantine', 'prep-registry-retirement', 'prep-runtime', 'prep-selection', 'prep-source-owner', 'prep-source-path', 'prep-source-total', 'prep-tag-custody', 'prep-tag-must-be-absent', 'prep-tag-retirement', 'prep-template', 'prep-template-job', 'prep-template-nonce', 'prep-template-pin', 'prep-view', 'prep-warm-cache', 'prep-warm-cache-required', 'template-decoded-cap', 'template-packed', 'template-packed-cap']), 'packet': frozenset(['P0-variant-source-drift', 'composed-map-binding-drift', 'composed-original-contract-refused', 'composed-original-recipes-refused', 'composed-packet-contract-refused', 'composed-policy-refused', 'composed-source-selection-refused', 'duplicate-json-key', 'exact-composed-metadata-pins-required', 'exact-metadata-pins-required', 'exact-reviewed-ksm-inputs-required', 'experiment-exporter-binding-drift', 'experiment-lock-refused', 'experiment-source-binding-drift', 'fixed-packet-path-required', 'full-github-sha-required', 'full-sha256-required', 'git-packet-binding-drift', 'git-packet-mode-refused', 'git-source-bytes-or-mode-drift', 'git-source-entry-refused', 'git-source-output-exceeded', 'git-source-path-count-exceeded', 'git-source-path-set-drift', 'git-source-query-failed', 'git-source-query-unavailable', 'github-checkout-commit-drift', 'ignored-executable-source-refused', 'initial-lock-binding-required', 'initial-lock-contract-refused', 'initial-recipe-binding-refused', 'initial-runner-tests-missing', 'initial-source-map-drift', 'invalid-git-source-tree', 'invalid-recipe-map', 'invalid-source-json', 'invalid-source-mode', 'invalid-source-row', 'metadata-pin-drift', 'new-external-snapshot-required', 'new-packet-output-required', 'nonfinite-json', 'packet-contract-refused', 'packet-initial-lock-binding-drift', 'packet-metadata-pin-drift', 'packet-size-exceeded', 'packet-source-map-drift', 'packet-source-tests-required', 'packet-write-failed', 'private-source-path', 'readonly-git-query-required', 'recipe-input-drift', 'recipe-input-omitted', 'recipe-map-required', 'required-source-tree-missing', 'reviewed-ksm-input-drift', 'reviewed-ksm-map-required', 'runtime-metadata-pins-drift', 'runtime-packet-path-required', 'singly-linked-source-required', 'snapshot-copy-drift', 'snapshot-copy-failed', 'snapshot-packet-binding-drift', 'snapshot-packet-required', 'snapshot-source-drift', 'snapshot-source-map-drift', 'source-changed-during-read', 'source-descriptor-close-failed', 'source-drift-during-freeze', 'source-drift-during-preflight', 'source-map-required', 'source-mode-or-size-refused', 'source-path-count-exceeded', 'source-python-cache-refused', 'source-read-failed', 'source-replaced-before-read', 'source-total-size-exceeded', 'source-unavailable', 'symlink-source-directory', 'symlink-source-refused', 'unreviewed-development-file', 'unsafe-source-path', 'virtual-metadata-binding-drift']), 'sdk': frozenset(['acceptance-failed', 'authority-failed', 'baseline-failed', 'callback-refused', 'cleanup-failed', 'crypto-failed', 'deadline', 'grant-refused', 'initial-failed', 'public-receiver-failed', 'restage-failed', 'source-refused', 'status-persistence-failed']), 'transport': frozenset(['Docker CLI bytes/owner/mode differ', 'EOF before ACK delivery', 'ancestor identity drift', 'bound typed Docker command required', 'bounded regular single-link input required', 'canonical literal bind required', 'child output byte bound', 'child supervision refused', 'closed transport', 'duplex callbacks required', 'empty private tool-state required', 'explicit allowlisted environment required', 'explicit duplex callbacks required', 'external Docker CLI pin required', 'externally observed endpoint identity required', 'finite pipe byte bound required', 'finite typed ACK required', 'finite unexpired transport deadline required', 'fixed endpoint socket identity drift', 'fixed local Docker environment required', 'foreign preparation quarantine registry', 'fresh CID file required', 'full private Docker CID required', 'input byte bound', 'input identity drift', 'literal bind differs', 'literal create mounts differ', 'literal original producer inputs differ', 'literal root-wrapper create policy differs', 'literal wrapper environment/entry differs', 'literal wrapper suffix differs', 'main-thread transport required', 'one exact repository scope required', 'original preparation work/cleanup endpoints required', 'owned private CID directory required', 'owned private tool-state mode required', 'parent traversal refused', 'pinned CLI identity drift', 'preparation module registry required', 'preparation natural/reaped status mismatch', 'preparation pending-signal bound', 'preparation quarantine forbids another birth', 'preparation signal-mask custody', 'preparation stream custody', 'preparation stream-close retry', 'private creation CID path differs', 'private tool-state directory required', 'private tool-state identity drift', 'producer exited before queued ACK delivery', 'producer stdin closed before ACK', 'registered create/source guard required', 'registered literal create validation required', 'unexpected Docker configuration/helper input', 'unsupported Docker operation', 'zero ACK write'])}
DIAGNOSTIC_TYPES = {'ValueError', 'TypeError', 'RuntimeError', 'OSError', 'KeyboardInterrupt', 'SystemExit', 'UNKNOWN'}
# prepare-image includes the signed-input audit as well as image construction.
# Project only fixed categories; never copy package names, fields or error text.
PREPARATION_REFUSALS = {
    'invalid, expired, revoked or unverified signature': 'prep-signature-audit',
    'signature does not match the pinned primary fingerprint': 'prep-signature-audit',
    'rootfs inventory differs from frozen signed-rootfs metadata': 'prep-input-metadata',
    'signed rootfs has no package inventory': 'prep-input-metadata',
    'oversized rootfs package metadata': 'prep-input-metadata',
    'nonregular installed package hook': 'prep-input-metadata',
    'invalid/oversized package metadata or hook': 'prep-input-metadata',
    'package has no .PKGINFO': 'prep-input-metadata',
    'this audited snapshot requires original .pkg.tar.xz bytes': 'prep-input-metadata',
    'duplicate download filename': 'prep-input-metadata',
    'unsafe ALPM hook mask name': 'prep-input-metadata',
    'audited input changed during Docker context copy': 'prep-image-contract',
    'bootstrap produced no immutable image ID': 'prep-image-id',
    'bootstrap image architecture differs from native ARM contract': 'prep-image-contract',
    'offline transaction changed the frozen package set; review packages.lock': 'prep-packages',
}
PREPARATION_PREFIXES = {
    'signed package metadata differs from frozen database: ': 'prep-input-metadata',
    'unsafe package path: ': 'prep-input-metadata',
    'duplicate package member: ': 'prep-input-metadata',
    'IMAGE_CONFIG ': 'prep-image-contract',
}
DIAGNOSTIC_CODES['pipeline'] |= frozenset(PREPARATION_REFUSALS.values()) | frozenset(PREPARATION_PREFIXES.values())
LEGACY_DIAGNOSTIC_CODES = frozenset().union(*DIAGNOSTIC_CODES.values())

# The selector and ordinal domain are fixed by the current reviewed input contract.
DOWNLOAD_OPERATIONS = frozenset('download-current-vim-v1-input-' + str(i).zfill(3) for i in range(501))
DOWNLOAD_CODE_TYPES = {'DL_HTTP_301': 'UNKNOWN', 'DL_HTTP_302': 'UNKNOWN', 'DL_HTTP_303': 'UNKNOWN', 'DL_HTTP_307': 'UNKNOWN', 'DL_HTTP_308': 'UNKNOWN', 'DL_HTTP_400': 'UNKNOWN', 'DL_HTTP_401': 'UNKNOWN', 'DL_HTTP_403': 'UNKNOWN', 'DL_HTTP_404': 'UNKNOWN', 'DL_HTTP_405': 'UNKNOWN', 'DL_HTTP_408': 'UNKNOWN', 'DL_HTTP_410': 'UNKNOWN', 'DL_HTTP_416': 'UNKNOWN', 'DL_HTTP_429': 'UNKNOWN', 'DL_HTTP_451': 'UNKNOWN', 'DL_HTTP_500': 'UNKNOWN', 'DL_HTTP_501': 'UNKNOWN', 'DL_HTTP_502': 'UNKNOWN', 'DL_HTTP_503': 'UNKNOWN', 'DL_HTTP_504': 'UNKNOWN', 'DL_HTTP_507': 'UNKNOWN', 'DL_HTTP_508': 'UNKNOWN', 'DL_HTTP_511': 'UNKNOWN', 'DL_HTTP_OTHER': 'UNKNOWN', 'DL_HTTP_UNKNOWN': 'UNKNOWN', 'DL_KBI_AFTER_PREP_ALRM': 'KeyboardInterrupt', 'DL_KBI_AFTER_UNATTRIBUTED': 'KeyboardInterrupt', 'DL_KBI_BEFORE_PREP_ALRM': 'KeyboardInterrupt', 'DL_KBI_BEFORE_UNATTRIBUTED': 'KeyboardInterrupt', 'DL_KBI_UNKNOWN_PREP_ALRM': 'KeyboardInterrupt', 'DL_KBI_UNKNOWN_UNATTRIBUTED': 'KeyboardInterrupt', 'DL_OSERROR': 'OSError', 'DL_OTHER': 'UNKNOWN', 'DL_RUNTIMEERROR': 'RuntimeError', 'DL_SYSTEMEXIT': 'SystemExit', 'DL_TIMEOUTERROR': 'OSError', 'DL_TYPEERROR': 'TypeError', 'DL_URLERROR': 'UNKNOWN', 'DL_VALUEERROR': 'ValueError', 'prep-download-cap': 'ValueError', 'prep-download-close-custody': 'ValueError', 'prep-download-domain': 'ValueError', 'prep-download-downgrade': 'ValueError', 'prep-download-fd': 'ValueError', 'prep-download-file': 'ValueError', 'prep-download-input': 'ValueError', 'prep-download-pin': 'ValueError', 'prep-download-progress': 'ValueError', 'prep-download-redirect': 'ValueError', 'prep-download-response-custody': 'ValueError', 'prep-download-target': 'ValueError', 'prep-fixed-four-no-HTTPS-fallback': 'ValueError', 'DL_GUARD_DEADLINE_BEFORE_OPEN': 'UNKNOWN', 'DL_GUARD_DEADLINE_BEFORE_CONNECT': 'UNKNOWN', 'DL_GUARD_DEADLINE_BEFORE_READ': 'UNKNOWN', 'DL_GUARD_DEADLINE_BEFORE_WRITE': 'UNKNOWN', 'DL_GUARD_DEADLINE_BEFORE_PUBLISH': 'UNKNOWN', 'DL_GUARD_DEADLINE_AFTER_PUBLISH': 'UNKNOWN'}
DOWNLOAD_CODES = frozenset(code for code in DOWNLOAD_CODE_TYPES if code.startswith('DL_'))
DOWNLOAD_GUARD_CODES = frozenset(DOWNLOAD_CODE_TYPES) - DOWNLOAD_CODES
DOWNLOAD_GUARD_DEADLINE_CODES = frozenset(('DL_GUARD_DEADLINE_BEFORE_OPEN', 'DL_GUARD_DEADLINE_BEFORE_CONNECT', 'DL_GUARD_DEADLINE_BEFORE_READ', 'DL_GUARD_DEADLINE_BEFORE_WRITE', 'DL_GUARD_DEADLINE_BEFORE_PUBLISH', 'DL_GUARD_DEADLINE_AFTER_PUBLISH'))
DIAGNOSTIC_STAGES['pipeline'] = DIAGNOSTIC_STAGES['pipeline'] | DOWNLOAD_OPERATIONS
DIAGNOSTIC_CODES['pipeline'] = DIAGNOSTIC_CODES['pipeline'] | DOWNLOAD_CODES


def exception_state(error):
    """Read builtin exception storage without subclass descriptors or hooks."""
    state = BaseException.__dict__['__dict__'].__get__(error)
    if type(state) is dict and all(type(key) is str for key in state):
        return state
    return None


def diagnostic(error, stage, operation, domain):
    """Pure closed facts; no error text, paths, arguments, payload or runtime rows."""
    need(stage in DIAGNOSTIC_STAGES and operation in DIAGNOSTIC_STAGES[stage] and operation not in DOWNLOAD_OPERATIONS and domain in DIAGNOSTIC_CODES,
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
    # Observed literal only: this does not attest exception class or Source origin.
    args = BaseException.__dict__['args'].__get__(error)
    if type(args) is tuple and len(args) == 1 and type(args[0]) is str and 0 < len(args[0]) <= 160 and args[0] in LEGACY_DIAGNOSTIC_CODES:
        code = args[0]
    if code == 'UNKNOWN' and stage == 'pipeline' and operation == 'prepare-image' and type(error) is ValueError and type(args) is tuple and len(args) == 1 and type(args[0]) is str:
        code = PREPARATION_REFUSALS.get(args[0], 'UNKNOWN')
        if code == 'UNKNOWN':
            for prefix, category in PREPARATION_PREFIXES.items():
                if args[0].startswith(prefix):
                    code = category
                    break
    return {'schema_version': 1, 'stage': stage, 'operation': operation, 'exception_type': kind, 'refusal_code': code}



def validate_diagnostic(value):
    """Closed carrier only; shape does not authenticate indexed-record origin."""
    if type(value) is not dict or len(value) != 5 or any(type(key) is not str for key in value) or set(value) != {'schema_version', 'stage', 'operation', 'exception_type', 'refusal_code'}:
        return None
    if type(value['schema_version']) is not int or value['schema_version'] != 1:
        return None
    if any(type(value[key]) is not str or not 0 < len(value[key]) <= 160 for key in ('stage', 'operation', 'exception_type', 'refusal_code')):
        return None
    if value['stage'] not in DIAGNOSTIC_STAGES or value['operation'] not in DIAGNOSTIC_STAGES[value['stage']] or value['exception_type'] not in DIAGNOSTIC_TYPES or value['refusal_code'] not in LEGACY_DIAGNOSTIC_CODES | DOWNLOAD_CODES | {'UNKNOWN'}:
        return None
    if value['operation'] in DOWNLOAD_OPERATIONS:
        if value['stage'] != 'pipeline' or value['refusal_code'] not in DOWNLOAD_CODE_TYPES or value['exception_type'] != DOWNLOAD_CODE_TYPES[value['refusal_code']]:
            return None
    elif value['refusal_code'] in DOWNLOAD_CODES:
        return None
    return {key: value[key] for key in ('schema_version', 'stage', 'operation', 'exception_type', 'refusal_code')}


def capture_download_accessor(module):
    """Capture only the plain function from the already authenticated driver body."""
    if type(module) is not types.ModuleType:
        return None
    state = types.ModuleType.__dict__['__dict__'].__get__(module)
    if type(state) is not dict or len(state) > 512 or any(type(key) is not str for key in state):
        return None
    function = state.get('download_diagnostic')
    if type(state.get('__name__')) is not str or state['__name__'] != 'development_p0_ci' or type(function) is not types.FunctionType:
        return None
    code = function.__code__
    if function.__globals__ is not state or type(function.__module__) is not str or function.__module__ != 'development_p0_ci' or type(function.__name__) is not str or function.__name__ != 'download_diagnostic' or type(function.__qualname__) is not str or function.__qualname__ != 'download_diagnostic' or function.__defaults__ is not None or function.__kwdefaults__ is not None or function.__closure__ is not None or code.co_argcount != 1 or code.co_kwonlyargcount or code.co_flags & 12:
        return None
    return module, state, function, code


def attach_diagnostic(error, stage, operation, domain, *, driver_accessor=None, accepted_context=None):
    """First closed record wins; only source-owned context authenticates indexing."""
    old = None
    legacy = None
    try:
        state = exception_state(error)
        if type(state) is not dict or not all(type(key) is str for key in state):
            return
        old = validate_diagnostic(state.get('nativeci_diagnostic'))
        if old is not None and old['operation'] not in DOWNLOAD_OPERATIONS:
            return
        # The public run wrapper owns this bounded context; exception attrs do not.
        if type(accepted_context) is list and len(accepted_context) == 1:
            primary, record = accepted_context[0]
            accepted = validate_diagnostic(record)
            if error is primary and accepted is not None and accepted['operation'] in DOWNLOAD_OPERATIONS:
                state['nativeci_diagnostic'] = accepted
                return accepted
        inner = state.get('nativeci_pipeline_operation')
        fallback = stage == 'pipeline' and operation == 'run-pipeline'
        if fallback and type(inner) is str and inner in DIAGNOSTIC_STAGES['pipeline'] - DOWNLOAD_OPERATIONS - {'run-pipeline', 'prepare-pipeline-arguments'}:
            operation = inner
        legacy = diagnostic(error, stage, operation, domain)
        if fallback and operation in {'download-input', 'download-http-error', 'download-url-error', 'download-timeout'} and (legacy['refusal_code'] == 'UNKNOWN' or legacy['refusal_code'] in DOWNLOAD_GUARD_CODES or legacy['refusal_code'] == 'deadline') and type(driver_accessor) is tuple and len(driver_accessor) == 4:
            module, module_state, function, code = driver_accessor
            captured = capture_download_accessor(module)
            if captured is not None and all(actual is expected for actual, expected in zip(captured, driver_accessor)):
                projected = validate_diagnostic(function(error))
                if projected is not None and projected['operation'] in DOWNLOAD_OPERATIONS and projected['exception_type'] == legacy['exception_type'] and (legacy['refusal_code'] not in DOWNLOAD_GUARD_CODES or projected['refusal_code'] == legacy['refusal_code']) and ((legacy['refusal_code'] == 'deadline') == (projected['refusal_code'] in DOWNLOAD_GUARD_DEADLINE_CODES)):
                    if type(accepted_context) is list and not accepted_context:
                        accepted_context.append((error, dict(projected)))
                    state['nativeci_diagnostic'] = projected
                    return projected
        state['nativeci_diagnostic'] = legacy
    except BaseException as secondary:
        # Restore the closed fallback independently of optional cancellation facts.
        try:
            state = exception_state(error)
            if state is not None and (old is None or old['operation'] in DOWNLOAD_OPERATIONS):
                state['nativeci_diagnostic'] = legacy if legacy is not None else diagnostic(error, stage, operation, domain)
        except BaseException:
            pass
        try:
            state = exception_state(error)
            if state is not None and any(base is KeyboardInterrupt for base in type.__dict__['__mro__'].__get__(type(secondary))):
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
    captured = {key: environment.pop(key) for key in tuple(environment) if key.startswith(('CACHY_OLD_FOUR_', 'CACHY_RETAINED_'))}
    expected = {'CACHY_OLD_FOUR_SCHEMA', 'CACHY_OLD_FOUR_SOURCE_EPOCH'}
    for tag, count in (('JBIGKIT', 2), ('JBIGKIT_SIG', 1), ('LIBTIFF', 15), ('LIBTIFF_SIG', 1)):
        expected.update('CACHY_OLD_FOUR_' + tag + '_' + str(index).zfill(2) for index in range(1, count + 1))
    retained = {'CACHY_RETAINED_BUBBLEWRAP_V1_PACKAGE_01': 32768,
                'CACHY_RETAINED_BUBBLEWRAP_V1_PACKAGE_02': 21136,
                'CACHY_RETAINED_BUBBLEWRAP_V1_SIGNATURE_01': 756}
    expected.update(retained)
    need(set(captured) == expected and captured['CACHY_OLD_FOUR_SCHEMA'] == '1'
         and captured['CACHY_OLD_FOUR_SOURCE_EPOCH'] == '1791748800', 'mandatory19-and-schema')
    for key, size in retained.items():
        value = captured[key]
        need(type(value) is str and len(value) == size and
             re.fullmatch('[A-Za-z0-9+/]*={0,2}', value) is not None, 'mandatory19-and-schema')
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
        preparation_sha256, P0_raw, P0_sha256, review_raw, review_sha256, environment, _download_context=None):
    need(type(entry) in (int, float) and math.isfinite(entry) and entry <= time.monotonic()
         and type(outer_end) in (int, float) and math.isfinite(outer_end), 'original-entry')
    end = min(entry + 60, outer_end - 90); live(end)
    captured = capture_four(environment)  # Before helper/provider/project code.
    first = None; result = None; driver_accessor = None
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
        driver_accessor = capture_download_accessor(module)
        need(not any(key.startswith(('CACHY_OLD_FOUR_', 'CACHY_RETAINED_')) for key in environment), 'seed-environment-drift')
        environment.update(captured)
        # No new preparation entry: all administration consumed its original frame.
        stage, operation, domain = 'pipeline', 'prepare-pipeline-arguments', 'pipeline'
        # Preserve original callable lookup and eight argument evaluations in order.
        pipeline_callable = module.pipeline
        pipeline_arguments = {'entry': entry, 'outer_end': outer_end, 'expected_source_commit': expected,
            'source_root': root, 'work_root': scratch.parent / ('prepared-P0-' + environment['GITHUB_RUN_ID'] + '-' + environment['GITHUB_RUN_ATTEMPT']),
            'cache': cache, 'prep_template_raw': module.packed_template(values['PREPARATION_BUNDLE_ZLIB_B64']),
            'prep_template_sha256': values['PREPARATION_BUNDLE_SHA256']}
        stage, operation, domain = 'pipeline', 'run-pipeline', 'pipeline'
        result = pipeline_callable(**pipeline_arguments)
    except BaseException as error:
        first = error
        attach_diagnostic(first, stage, operation, domain, driver_accessor=driver_accessor, accepted_context=_download_context)
    finally:
        try:
            captured.clear()
            for key in tuple(environment):
                if key.startswith(('CACHY_OLD_FOUR_', 'CACHY_RETAINED_')):
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
    accepted_context = []
    try:
        return _run(entry=entry, outer_end=outer_end, root=root, scratch=scratch, cache=cache,
            proof_raw=proof_raw, proof_sha256=proof_sha256, preparation_raw=preparation_raw,
            preparation_sha256=preparation_sha256, P0_raw=P0_raw, P0_sha256=P0_sha256,
            review_raw=review_raw, review_sha256=review_sha256, environment=environment, _download_context=accepted_context)
    except BaseException as error:
        attach_diagnostic(error, 'entry', 'validate-entry', 'launcher', accepted_context=accepted_context)
        raise
