#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root-pinned prerequisite DATA only. No signing, archive parsing, actors or fetch."""
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat

OPERATION = 'perl5423-installed-lifecycle-native-v1'
INNER_OPERATION = 'perl5423-installed-lifecycle-v1'
SCOPE = 'ROOT_INPUT_REVIEW_ONLY_NOT_IMAGE_OR_RUNTIME_QUALIFICATION'
STATUS = 'ROOT_REVIEWED_PREREQUISITES_FOR_SINGLE_NATIVE_LIFECYCLE'
SOURCE = '25dc3e65bdb6137c87a9409067fe9b2cf6e9763f'
RUN = '43692477455'
SIGNER = '68B3537F39A313B3E574D06777193F152BDBE6A6'
OLD = {'bytes': 16017184, 'sha256': 'f0e47c42ec91985898af2ce7355ef4eead50457108706add1f8c1650bca19b8f'}
OLD_SIG = {'bytes': 566, 'sha256': 'f40e70ac18f61c8b706c7642bac2cfef7b4fcb9d96bd30da3fc41c48a6667dca'}
CANDIDATE = {'bytes': 22071176, 'sha256': '647c5f1d2c6965ec2e26b37e75d29c819fafa344f16002153493e9fc62121c22'}
DECISION = {'bytes': 5804, 'sha256': '27803c99064198f8688abe2e4d91910eef93df5ad337ebfc7f2d8798afbf41e1'}
LOCK_SHA = 'b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9'
EXPECTED_SHA = '579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453'
INPUT_NAMES = ('baseline_lock', 'expected349', 'candidate', 'candidate_signature', 'baseline', 'baseline_signature', 'public_keyring', 'public_trustdb', 'test_public')
CAPSULE_NAMES = {
    'baseline_lock': 'baseline-inputs.lock.json', 'expected349': 'expected349.lock',
    'candidate': 'perl-5.42.3-1.3-aarch64.pkg.tar.zst',
    'candidate_signature': 'perl-5.42.3-1.3-aarch64.pkg.tar.zst.sig',
    'baseline': 'perl-5.42.3-1-aarch64.pkg.tar.xz',
    'baseline_signature': 'perl-5.42.3-1-aarch64.pkg.tar.xz.sig',
    'public_keyring': 'trust/pubring.gpg', 'public_trustdb': 'trust/trustdb.gpg',
    'test_public': 'test-public.asc',
}
HOOK_ROOTS = ('/builder-disabled-hooks', '/etc/pacman.d/hooks', '/usr/share/libalpm/hooks')
EFFECTIVE_POLICY = {
    'transaction_config': '/work/pacman.conf',
    'transaction_hookdir': 'NO_HOOKDIR_DIRECTIVE_ALPM_DEFAULT_DIRECTORIES',
    'bootstrap_config': '/etc/pacman.conf',
    'bootstrap_hookdir': '/builder-disabled-hooks',
    'equivalence': 'NOT_EQUIVALENT_EFFECTIVE_HOOK_POLICY_REQUIRES_SEPARATE_ROOT_REVIEW',
    'global_config_preservation': 'BYTE_PRESERVATION_DOES_NOT_PROVE_EFFECTIVE_TRANSACTION_POLICY',
}
PUBLIC_BASELINE_POLICY = 'OBSERVE_FRESH_BOOTSTRAP_PUBLIC_FILES_NO_PREDICTED_LOCAL_KEY_BYTES'
MIB = 1024**2


def need(ok, why):
    if not ok:
        raise ValueError(why)


def is_digest(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def read(path, cap):
    """Bounded same-FD read through ordinary no-follow directory ancestry."""
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and not any(c in str(path) for c in '\0\n\r'), 'ordinary absolute input path required')
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            os.close(parent)
            parent = child
        leaf = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        try:
            before = os.fstat(leaf)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= cap, 'bounded ordinary single-link input required')
            raw = bytearray()
            while block := os.read(leaf, min(65536, cap+1-len(raw))):
                raw.extend(block)
                need(len(raw) <= cap, 'input byte cap exceeded')
            key = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_uid, s.st_gid, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            need(len(raw) == before.st_size and key(before) == key(os.fstat(leaf)) == key(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'input changed during read')
            # Also reject replacement of any path ancestry during the operation.
            need(key(before) == key(path.lstat()) and not any(p.is_symlink() for p in path.parents), 'input path changed or aliased')
            return bytes(raw), stat.S_IMODE(before.st_mode)
        finally:
            os.close(leaf)
    finally:
        os.close(parent)


def decode(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    def invalid(_value):
        raise ValueError('nonfinite JSON')
    def real(value):
        number = float(value)
        need(math.isfinite(number), 'nonfinite JSON')
        return number
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid, parse_float=real)
    except RecursionError as error:
        raise ValueError('bounded JSON depth required') from error
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        need(depth <= 32 and count <= 100000, 'bounded JSON structure required')
        if type(item) is dict:
            pending.extend((v, depth+1) for v in item.values())
        elif type(item) is list:
            pending.extend((v, depth+1) for v in item)
    need(type(value) is dict, 'JSON object required')
    return value


def file_input(row, cap=64*MIB, fixed=None):
    need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256', 'mode'}, 'concrete complete input descriptor required')
    need(type(row['path']) is str and type(row['bytes']) is int and 0 < row['bytes'] <= cap and is_digest(row['sha256']), 'missing concrete input path/size/hash')
    need(type(row['mode']) is int and 0 <= row['mode'] <= 0o777, 'ordinary exact admitted file mode required')
    if fixed is not None:
        need({k: row[k] for k in ('bytes', 'sha256')} == fixed, 'different fixed archive/signature/decision declaration')
    raw, mode = read(Path(row['path']), cap)
    need(pin(raw) == {k: row[k] for k in ('bytes', 'sha256')} and mode == row['mode'], 'input bytes or exact admitted mode differ')
    return Path(row['path']), raw


def path_record(row):
    need(type(row) is dict and row.get('type') in ('file', 'directory', 'symlink', 'absent'), 'reviewed filesystem expectation required')
    kind = row['type']
    if kind == 'absent':
        need(set(row) == {'type'}, 'exact absent-path expectation')
        return
    need(type(row.get('mode')) is int and 0 <= row['mode'] <= 0o7777, 'exact filesystem mode expectation required')
    if kind == 'file':
        need(set(row) == {'type','mode','bytes','sha256'} and type(row['bytes']) is int and 0 <= row['bytes'] <= 16*MIB and is_digest(row['sha256']), 'complete config/hook file expectation')
    elif kind == 'symlink':
        need(set(row) == {'type','mode','target'} and type(row['target']) is str and 0 < len(row['target']) <= 4096, 'exact hook symlink expectation')
    else:
        need(set(row) == {'type','mode'}, 'exact directory expectation')


def image_expectations(value):
    need(type(value) is dict and value.get('reviewed') is True and value.get('complete_hook_snapshots') is True, 'Root-reviewed config and complete hook expectations required')
    configs = value['config_files']
    need(type(configs) is dict and set(configs) == {'/etc/pacman.conf'}, 'exact baseline pacman config expectation required')
    path_record(configs['/etc/pacman.conf'])
    need(configs['/etc/pacman.conf']['type'] == 'file', 'baseline pacman config must be a reviewed file')
    hooks = value['hook_snapshots']
    need(type(hooks) is dict and set(hooks) == set(HOOK_ROOTS), 'all effective and masked hook roots require review')
    total = 0
    for root, rows in hooks.items():
        need(type(rows) is dict and '.' in rows and 1 <= len(rows) <= 4096, 'complete hook-root snapshot required')
        for name, row in rows.items():
            need(type(name) is str and (name == '.' or (not name.startswith('/') and all(p not in ('', '.', '..') for p in name.split('/')))), 'contained exact hook snapshot path')
            path_record(row)
            total += 1
        need(rows['.']['type'] in ('directory', 'absent') and (rows['.']['type'] != 'absent' or len(rows) == 1), 'hook root must be directory or explicitly absent')
    need(total <= 8192 and value['baseline_public_trust'] == PUBLIC_BASELINE_POLICY, 'bounded hooks and observed fresh baseline public trust policy required')


def archive_review(value):
    need(value.get('status') == 'ROOT_ARCHIVE_REVIEW_REQUIRED_BEFORE_ADMISSION' and value.get('archive') == OLD and value.get('signature') == OLD_SIG, 'exact held archive-derived review identity required')
    rows = value.get('metadata_config_hook_paths')
    need(type(rows) is dict and 1 <= len(rows) <= 8192 and '.PKGINFO' in rows, 'reviewed baseline ALPM metadata/config/hook map required')
    for name, row in rows.items():
        need(type(name) is str and not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts and name.startswith(('.', 'etc/', 'usr/share/libalpm/')) and type(row) is dict, 'exact contained archive-review paths required')


def validate(path, expected_sha):
    need(is_digest(expected_sha), 'explicit external Root review SHA256 required')
    raw, _mode = read(Path(path), 4*MIB)
    need(pin(raw)['sha256'] == expected_sha, 'Root prerequisite review changed')
    r = decode(raw)
    need(r.get('schema') == 1 and r.get('operation') == OPERATION and r.get('inner_operation') == INNER_OPERATION and r.get('scope') == SCOPE, 'finite lifecycle prerequisite review scope required')
    need(r.get('status') == STATUS and r.get('authority') == 'Root' and r.get('holds_preserved') is True, 'prerequisites remain unreviewed; no Root authority inferred')
    file_input(r['review_evidence'], 4*MIB)
    inputs = r['inputs']
    need(type(inputs) is dict and set(inputs) == set(INPUT_NAMES), 'exact held prepare input set required')
    fixed = {'candidate': CANDIDATE, 'baseline': OLD, 'baseline_signature': OLD_SIG}
    paths, bodies = {}, {}
    for name in INPUT_NAMES:
        paths[name], bodies[name] = file_input(inputs[name], fixed=fixed.get(name))
    need(pin(bodies['baseline_lock'])['sha256'] == LOCK_SHA and pin(bodies['expected349'])['sha256'] == EXPECTED_SHA, 'exact genuine349 frozen lock/inventory required')
    rows = bodies['expected349'].decode().splitlines()
    need(len(rows) == 349 and rows == sorted(set(rows)) and dict(row.split(' ', 1) for row in rows).get('perl') == '5.42.3-1', 'exact baseline Perl inventory required')
    need(100 < len(bodies['candidate_signature']) < 2048, 'fresh externally supplied TEST detached signature required')
    need(b'-----BEGIN PGP PUBLIC KEY BLOCK-----' in bodies['test_public'] and b'PRIVATE' not in bodies['test_public'], 'public TEST certificate only')
    accepted = r['accepted_candidate']
    need(accepted['build_source'] == SOURCE and accepted['native_run'] == RUN and accepted['archive'] == CANDIDATE, 'accepted candidate Source/run/archive differs')
    _, decision_raw = file_input(accepted['decision'], 64*1024, DECISION)
    decision = decode(decision_raw)
    need(decision['issuer'] == 'Root' and decision['accepted'] is True and decision['status'] == 'ACCEPTED_EXACT_PERL5423_NATIVE_ARM4K_BUILD_PAIR_ONLY' and decision['archive'] == CANDIDATE and decision['binding']['source'] == SOURCE and decision['binding']['run'] == RUN, 'Root accepted build decision join differs')
    trust = r['trust_review']
    need(trust['reviewed'] is trust['public_only'] is trust['fresh_test_signature_external'] is True and trust['signing_credentials'] == 'EXCLUDED; fresh Root TEST signing performed outside actors', 'public-only externally signed trust review required')
    need(type(trust['test_fingerprint']) is str and re.fullmatch('[0-9A-F]{40}', trust['test_fingerprint']) and trust['baseline_fingerprint'] == SIGNER and trust['test_fingerprint'] != SIGNER, 'distinct explicit TEST and original baseline primary fingerprints required')
    need(trust['test_uid_policy'] == 'TEST ONLY; @test.invalid' and trust['combined_trust_pins_reviewed'] is True, 'exact TEST UID and combined public trust pins need Root review')
    baseline = r['baseline_review']
    need(baseline['reviewed'] is True and baseline['install_metadata_config_hooks_reviewed'] is True, 'baseline .INSTALL/config/hook review remains missing')
    _, baseline_raw = file_input(baseline['archive_review'], 4*MIB)
    archive_review(decode(baseline_raw))
    need(r['effective_policy'] == dict(EFFECTIVE_POLICY, reviewed=True), 'effective lifecycle NO HookDir policy must be reviewed separately from bootstrap masks')
    image_expectations(r['image_expectations'])
    return dict(review=r, review_sha256=expected_sha, paths=paths)


def check_capsule_review(capsule, review):
    """Rejoin a sealed capsule to Root's already-pinned archive-review DATA."""
    need(review.get('status') == STATUS and review.get('authority') == 'Root' and review['baseline_review']['reviewed'] is True, 'prior concrete Root prerequisite review required')
    _, expected_raw = file_input(review['baseline_review']['archive_review'], 4*MIB)
    expected = decode(expected_raw)
    archive_review(expected)
    actual_raw, _mode = read(Path(capsule)/'baseline-review.json', 4*MIB)
    actual = decode(actual_raw)
    archive_review(actual)
    need(actual == expected and actual['metadata_config_hook_paths'] == expected['metadata_config_hook_paths'], 'generated baseline-review differs from exact Root-reviewed metadata/config/hooks')
    # prepare() rereads caller paths; join copied bytes again so a post-gate
    # change of a signature or public trust input cannot become sealed DATA.
    for argument, name in CAPSULE_NAMES.items():
        body, mode = read(Path(capsule)/name, 64*MIB)
        need(pin(body) == {k: review['inputs'][argument][k] for k in ('bytes', 'sha256')} and mode == 0o444, 'sealed capsule input differs from Root-reviewed bytes: '+argument)
    return dict(status='EXACT_CAPSULE_REVIEW_DATA_JOINED', baseline_review=pin(actual_raw), root_review_status=review['status'], image_runtime_qualification='NOT_ISSUED_BY_THIS_CHECK')
